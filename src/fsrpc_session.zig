const std = @import("std");
const unified = @import("ziggy-spider-protocol").unified;
const runtime_server_mod = @import("runtime_server.zig");

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
    allocator: std.mem.Allocator,
    runtime_server: *runtime_server_mod.RuntimeServer,

    nodes: std.AutoHashMapUnmanaged(u32, Node) = .{},
    fids: std.AutoHashMapUnmanaged(u32, FidState) = .{},
    pending_debug_frames: std.ArrayListUnmanaged([]u8) = .{},
    debug_stream_enabled: bool = false,

    next_node_id: u32 = 1,
    next_job_id: u32 = 1,

    root_id: u32 = 0,
    jobs_root_id: u32 = 0,
    chat_input_id: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        runtime_server: *runtime_server_mod.RuntimeServer,
        agent_id: []const u8,
    ) !Session {
        var self = Session{
            .allocator = allocator,
            .runtime_server = runtime_server,
        };
        try self.seedNamespace(agent_id);
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
        self.* = undefined;
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
        const msg_type = msg.fsrpc_type orelse {
            return unified.buildFsrpcError(self.allocator, msg.tag, "invalid_type", "missing fsrpc message type");
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
            else => unified.buildFsrpcError(self.allocator, msg.tag, "unsupported", "unsupported fsrpc operation"),
        };
    }

    fn handleVersion(self: *Session, msg: *const unified.ParsedMessage) ![]u8 {
        const msize = msg.msize orelse 1_048_576;
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"msize\":{d},\"version\":\"styx-lite-1\"}}",
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
        defer if (job_name) |value| self.allocator.free(value);
        switch (node.special) {
            .chat_input => {
                const outcome = try self.handleChatInputWrite(data);
                written = outcome.written;
                job_name = outcome.job_name;
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
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"n\":{d},\"job\":\"{s}\",\"result_path\":\"/jobs/{s}/result.txt\"}}",
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

    fn seedNamespace(self: *Session, agent_id: []const u8) !void {
        self.root_id = try self.addDir(null, "/", false);
        _ = try self.addDir(self.root_id, "workspace", false);

        const capabilities = try self.addDir(self.root_id, "capabilities", false);
        const chat = try self.addDir(capabilities, "chat", false);

        const help_md =
            "# Chat Capability\n\n" ++
            "Write UTF-8 text to `control/input` to create a chat job.\n" ++
            "Read `/jobs/<job-id>/result.txt` for assistant output.\n";
        _ = try self.addFile(chat, "help.md", help_md, false, .none);

        const schema_json =
            "{\"name\":\"chat\",\"input\":\"control/input\",\"jobs\":\"/jobs\",\"result\":\"result.txt\"}";
        _ = try self.addFile(chat, "schema.json", schema_json, false, .none);

        const escaped_agent = try unified.jsonEscape(self.allocator, agent_id);
        defer self.allocator.free(escaped_agent);
        const meta_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"name\":\"chat\",\"version\":\"1\",\"agent_id\":\"{s}\",\"cost_hint\":\"provider-dependent\",\"latency_hint\":\"seconds\"}}",
            .{escaped_agent},
        );
        defer self.allocator.free(meta_json);
        _ = try self.addFile(chat, "meta.json", meta_json, false, .none);

        const examples = try self.addDir(chat, "examples", false);
        _ = try self.addFile(examples, "send.txt", "hello from fsrpc chat", false, .none);

        const control = try self.addDir(chat, "control", false);
        self.chat_input_id = try self.addFile(control, "input", "", true, .chat_input);

        self.jobs_root_id = try self.addDir(self.root_id, "jobs", false);

        const meta = try self.addDir(self.root_id, "meta", false);
        const protocol_json =
            "{\"channel\":\"fsrpc\",\"version\":\"styx-lite-1\",\"ops\":[\"t_version\",\"t_attach\",\"t_walk\",\"t_open\",\"t_read\",\"t_write\",\"t_stat\",\"t_clunk\",\"t_flush\"]}";
        _ = try self.addFile(meta, "protocol.json", protocol_json, false, .none);
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

    fn handleChatInputWrite(self: *Session, raw_input: []const u8) !WriteOutcome {
        const input = std.mem.trim(u8, raw_input, " \t\r\n");
        if (input.len == 0) {
            return .{ .written = 0, .job_name = null };
        }

        const job_name = try std.fmt.allocPrint(self.allocator, "job-{d}", .{self.next_job_id});
        self.next_job_id += 1;
        defer self.allocator.free(job_name);

        const job_dir = try self.addDir(self.jobs_root_id, job_name, false);
        const status_id = try self.addFile(job_dir, "status.json", "{\"state\":\"running\"}", true, .job_status);
        const result_id = try self.addFile(job_dir, "result.txt", "", true, .job_result);
        const log_id = try self.addFile(job_dir, "log.txt", "", true, .job_log);

        const escaped = try unified.jsonEscape(self.allocator, input);
        defer self.allocator.free(escaped);
        const runtime_req = try std.fmt.allocPrint(
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
        if (self.runtime_server.handleMessageFramesWithDebug(runtime_req, self.debug_stream_enabled)) |frames| {
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
                        if (obj.get("message")) |msg| {
                            if (msg == .string) {
                                if (failure_message_owned) |owned| self.allocator.free(owned);
                                failure_message_owned = try self.allocator.dupe(u8, msg.string);
                                failure_message = failure_message_owned.?;
                            }
                        }
                    }
                }
            }
        }

        if (failed) {
            const escaped_failure = try unified.jsonEscape(self.allocator, failure_message);
            defer self.allocator.free(escaped_failure);
            const status = try std.fmt.allocPrint(self.allocator, "{{\"state\":\"failed\",\"error\":\"{s}\"}}", .{escaped_failure});
            defer self.allocator.free(status);
            try self.setFileContent(status_id, status);
            try self.setFileContent(result_id, failure_message);
        } else {
            try self.setFileContent(status_id, "{\"state\":\"complete\"}");
            try self.setFileContent(result_id, result_text);
        }

        const log_content = try log_buf.toOwnedSlice(self.allocator);
        defer self.allocator.free(log_content);
        try self.setFileContent(log_id, log_content);

        return .{
            .written = raw_input.len,
            .job_name = try self.allocator.dupe(u8, job_name),
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

    var runtime_server = try runtime_server_mod.RuntimeServer.create(allocator, "default", .{});
    defer runtime_server.destroy();

    var session = try Session.init(allocator, runtime_server, "default");
    defer session.deinit();

    var attach = unified.ParsedMessage{
        .channel = .fsrpc,
        .fsrpc_type = .t_attach,
        .tag = 1,
        .fid = 1,
    };
    const attach_res = try session.handle(&attach);
    defer allocator.free(attach_res);
    try std.testing.expect(std.mem.indexOf(u8, attach_res, "fsrpc.r_attach") != null);

    const path = try allocator.alloc([]u8, 2);
    path[0] = try allocator.dupe(u8, "capabilities");
    path[1] = try allocator.dupe(u8, "chat");
    defer {
        allocator.free(path[0]);
        allocator.free(path[1]);
        allocator.free(path);
    }

    var walk = unified.ParsedMessage{
        .channel = .fsrpc,
        .fsrpc_type = .t_walk,
        .tag = 2,
        .fid = 1,
        .newfid = 2,
        .path = path,
    };
    const walk_res = try session.handle(&walk);
    defer allocator.free(walk_res);
    try std.testing.expect(std.mem.indexOf(u8, walk_res, "fsrpc.r_walk") != null);
}
