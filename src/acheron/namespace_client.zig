const builtin = @import("builtin");
const std = @import("std");
const mount_provider = @import("spiderweb_mount_provider");
const unified = @import("spider-protocol").unified;

const control_reply_timeout_ms: i32 = 45_000;
const control_handshake_timeout_ms: i32 = 10_000;
const session_status_poll_interval_ms: u64 = 250;
const slow_readdir_warn_ms: u64 = 100;
const synthetic_statfs_json =
    "{\"bsize\":65536,\"frsize\":65536,\"blocks\":1,\"bfree\":1,\"bavail\":1,\"files\":1048576,\"ffree\":1048575,\"favail\":1048575,\"namemax\":4096}";

pub const NamespaceHandle = mount_provider.NamespaceHandle;

pub const NamespaceStat = struct {
    id: u64,
    kind: Kind,
    size: u64,
    mode: u32,
    writable: bool,

    pub const Kind = enum {
        dir,
        file,
    };
};

pub const ConnectInfo = struct {
    agent_id: ?[]u8 = null,
    project_id: ?[]u8 = null,
    session_key: ?[]u8 = null,
    requires_session_attach: bool = false,
    workspace_json: ?[]u8 = null,
    has_workspace_mounts: bool = false,

    pub fn deinit(self: *ConnectInfo, allocator: std.mem.Allocator) void {
        if (self.agent_id) |value| allocator.free(value);
        if (self.project_id) |value| allocator.free(value);
        if (self.session_key) |value| allocator.free(value);
        if (self.workspace_json) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const SessionAttachRequest = struct {
    session_key: []const u8,
    agent_id: []const u8,
    project_id: []const u8,
    project_token: ?[]const u8 = null,
};

pub const SessionAttachInfo = struct {
    session_key: []u8,
    agent_id: []u8,
    project_id: []u8,

    pub fn deinit(self: *SessionAttachInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.session_key);
        allocator.free(self.agent_id);
        allocator.free(self.project_id);
        self.* = undefined;
    }
};

const SessionAttachState = enum {
    warming,
    ready,
    err,
};

const SessionStatusInfo = struct {
    attach_state: SessionAttachState,
    error_code: ?[]u8 = null,

    fn deinit(self: *SessionStatusInfo, allocator: std.mem.Allocator) void {
        if (self.error_code) |value| allocator.free(value);
        self.* = undefined;
    }
};

const OpenHandleState = struct {
    path: []u8,
    flags: u32,
    fid: u32,
    writable: bool,

    fn deinit(self: *OpenHandleState, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub const NamespaceClient = struct {
    allocator: std.mem.Allocator,
    namespace_url: []u8,
    auth_token: ?[]u8 = null,
    stream: std.net.Stream,
    next_control_id: u64 = 1,
    next_tag: u32 = 1,
    next_fid: u32 = 2,
    root_fid: u32 = 1,
    namespace_attached: bool = false,
    active_session_key: ?[]u8 = null,
    active_agent_id: ?[]u8 = null,
    active_project_id: ?[]u8 = null,
    active_project_token: ?[]u8 = null,
    next_handle_id: u64 = 1,
    open_handles: std.AutoHashMapUnmanaged(u64, OpenHandleState) = .{},

    pub fn connect(
        allocator: std.mem.Allocator,
        namespace_url: []const u8,
        auth_token: ?[]const u8,
    ) !NamespaceClient {
        const parsed = try parseWsUrlWithDefaultPath(namespace_url, "/");
        var stream = try std.net.tcpConnectToHost(allocator, parsed.host, parsed.port);
        var stream_owned_by_client = false;
        errdefer if (!stream_owned_by_client) stream.close();
        try configureSocketForControl(&stream);

        try performClientHandshake(
            allocator,
            &stream,
            parsed.host,
            parsed.port,
            parsed.path,
            auth_token,
        );

        var client = NamespaceClient{
            .allocator = allocator,
            .namespace_url = try allocator.dupe(u8, namespace_url),
            .auth_token = if (auth_token) |token| try allocator.dupe(u8, token) else null,
            .stream = stream,
        };
        stream_owned_by_client = true;
        errdefer client.deinit();
        try client.negotiateControlVersion();
        return client;
    }

    pub fn deinit(self: *NamespaceClient) void {
        var open_it = self.open_handles.iterator();
        while (open_it.next()) |entry| {
            var state = entry.value_ptr.*;
            state.deinit(self.allocator);
        }
        self.open_handles.deinit(self.allocator);
        if (self.active_session_key) |value| self.allocator.free(value);
        if (self.active_agent_id) |value| self.allocator.free(value);
        if (self.active_project_id) |value| self.allocator.free(value);
        if (self.active_project_token) |value| self.allocator.free(value);
        if (self.auth_token) |value| self.allocator.free(value);
        self.allocator.free(self.namespace_url);
        self.stream.close();
        self.* = undefined;
    }

    pub fn controlConnect(self: *NamespaceClient) !ConnectInfo {
        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);

        try self.writeControlRequest("control.connect", request_id, "{}");
        const payload_json = try readControlPayloadFor(self, request_id, "control.connect_ack");
        defer self.allocator.free(payload_json);

        return parseConnectInfo(self.allocator, payload_json);
    }

    pub fn controlAgentEnsure(self: *NamespaceClient, agent_id: []const u8) !void {
        const escaped_agent = try jsonEscape(self.allocator, agent_id);
        defer self.allocator.free(escaped_agent);
        const payload = try std.fmt.allocPrint(self.allocator, "{{\"agent_id\":\"{s}\"}}", .{escaped_agent});
        defer self.allocator.free(payload);

        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);
        try self.writeControlRequest("control.agent_ensure", request_id, payload);
        const response_payload = try readControlPayloadFor(self, request_id, "control.agent_ensure");
        self.allocator.free(response_payload);
    }

    pub fn controlSessionAttach(self: *NamespaceClient, request: SessionAttachRequest) !SessionAttachInfo {
        const escaped_session = try jsonEscape(self.allocator, request.session_key);
        defer self.allocator.free(escaped_session);
        const escaped_agent = try jsonEscape(self.allocator, request.agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = try jsonEscape(self.allocator, request.project_id);
        defer self.allocator.free(escaped_project);

        const payload = if (request.project_token) |token| blk: {
            const escaped_token = try jsonEscape(self.allocator, token);
            defer self.allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                .{ escaped_session, escaped_agent, escaped_project, escaped_token },
            );
        } else try std.fmt.allocPrint(
            self.allocator,
            "{{\"session_key\":\"{s}\",\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}",
            .{ escaped_session, escaped_agent, escaped_project },
        );
        defer self.allocator.free(payload);

        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);
        try self.writeControlRequest("control.session_attach", request_id, payload);
        const payload_json = try readControlPayloadFor(self, request_id, "control.session_attach");
        defer self.allocator.free(payload_json);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;

        const session_key = getRequiredString(parsed.value.object, "session_key") orelse return error.InvalidResponse;
        const agent_id = getRequiredString(parsed.value.object, "agent_id") orelse return error.InvalidResponse;
        const project_id = getRequiredString(parsed.value.object, "project_id") orelse return error.InvalidResponse;
        try self.setActiveSessionKey(session_key);
        try self.setActiveSessionBinding(request.agent_id, request.project_id, request.project_token);

        return .{
            .session_key = try self.allocator.dupe(u8, session_key),
            .agent_id = try self.allocator.dupe(u8, agent_id),
            .project_id = try self.allocator.dupe(u8, project_id),
        };
    }

    pub fn controlWorkspaceStatus(self: *NamespaceClient, project_id: ?[]const u8, project_token: ?[]const u8) ![]u8 {
        const payload = if (project_id) |selected_project| blk: {
            const escaped_project = try jsonEscape(self.allocator, selected_project);
            defer self.allocator.free(escaped_project);
            if (project_token) |token| {
                const escaped_token = try jsonEscape(self.allocator, token);
                defer self.allocator.free(escaped_token);
                break :blk try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
                    .{ escaped_project, escaped_token },
                );
            }
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"project_id\":\"{s}\"}}",
                .{escaped_project},
            );
        } else try self.allocator.dupe(u8, "{}");
        defer self.allocator.free(payload);

        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);
        try self.writeControlRequest("control.workspace_status", request_id, payload);
        return readControlPayloadFor(self, request_id, "control.workspace_status");
    }

    pub fn attachNamespaceRoot(self: *NamespaceClient, session_key: []const u8) !void {
        try self.setActiveSessionKey(session_key);
        const version_payload = try self.callAcheron(
            .t_version,
            .r_version,
            "\"msize\":1048576,\"version\":\"acheron-1\"",
        );
        self.allocator.free(version_payload);

        const attach_payload = try self.callAcheron(.t_attach, .r_attach, "\"fid\":1");
        self.allocator.free(attach_payload);
        self.namespace_attached = true;
        self.next_fid = 2;
    }

    pub fn keepActiveSessionAlive(self: *NamespaceClient) !void {
        const session_key = self.active_session_key orelse return;
        var status = blk: {
            break :blk self.controlSessionStatus(session_key, true) catch |err| {
                if (!isTransportError(err)) return err;
                try self.recoverActiveSessionTransport(session_key);
                break :blk try self.controlSessionStatus(session_key, true);
            };
        };
        status.deinit(self.allocator);
    }

    pub fn getattr(self: *NamespaceClient, path: []const u8) ![]u8 {
        return self.getattrOnce(path) catch |err| {
            if (!isTransportError(err)) return err;
            const session_key = self.active_session_key orelse return err;
            try self.recoverActiveSessionTransport(session_key);
            return self.getattrOnce(path);
        };
    }

    fn getattrOnce(self: *NamespaceClient, path: []const u8) ![]u8 {
        const stat = try self.statPath(path);
        return self.statToAttrJson(stat);
    }

    pub fn readdir(self: *NamespaceClient, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        return self.readdirOnce(path, cookie, max_entries) catch |err| {
            if (!isTransportError(err)) return err;
            const session_key = self.active_session_key orelse return err;
            try self.recoverActiveSessionTransport(session_key);
            return self.readdirOnce(path, cookie, max_entries);
        };
    }

    fn readdirOnce(self: *NamespaceClient, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        var timer = try std.time.Timer.start();
        const stat = try self.statPath(path);
        if (stat.kind != .dir) return error.NotDirectory;

        const fid = try self.walkPathToNewFid(path);
        defer self.clunk(fid) catch {};

        try self.openFid(fid, "r");
        const listing = try self.readAll(fid, 0, 1_048_576);
        defer self.allocator.free(listing);

        var names = std.ArrayListUnmanaged([]const u8){};
        defer names.deinit(self.allocator);
        try names.append(self.allocator, ".");
        try names.append(self.allocator, "..");

        var line_it = std.mem.splitScalar(u8, listing, '\n');
        while (line_it.next()) |name| {
            if (name.len == 0) continue;
            try names.append(self.allocator, name);
        }

        const start_index = std.math.cast(usize, cookie) orelse return error.Range;
        if (start_index >= names.items.len) {
            return self.allocator.dupe(u8, "{\"ents\":[],\"next\":0,\"eof\":true,\"dir_gen\":0}");
        }

        const max_count: usize = if (max_entries == 0) 0 else max_entries;
        const end_index = @min(names.items.len, start_index + max_count);
        const eof = end_index >= names.items.len;

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"ents\":[");
        for (names.items[start_index..end_index], 0..) |name, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped_name = try jsonEscape(self.allocator, name);
            defer self.allocator.free(escaped_name);
            try out.writer(self.allocator).print("{{\"name\":\"{s}\"}}", .{escaped_name});
        }
        try out.writer(self.allocator).print(
            "],\"next\":{d},\"eof\":{s},\"dir_gen\":0}}",
            .{ end_index, if (eof) "true" else "false" },
        );
        const elapsed_ms = timer.read() / std.time.ns_per_ms;
        if (elapsed_ms >= slow_readdir_warn_ms) {
            std.log.warn("slow namespace readdir: {d}ms path={s} cookie={d} max_entries={d}", .{
                elapsed_ms,
                path,
                cookie,
                max_entries,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }

    pub fn statfs(self: *NamespaceClient, path: []const u8) ![]u8 {
        _ = path;
        return self.allocator.dupe(u8, synthetic_statfs_json);
    }

    pub fn open(self: *NamespaceClient, path: []const u8, flags: u32) !NamespaceHandle {
        return self.openOnce(path, flags) catch |err| {
            if (!isTransportError(err)) return err;
            const session_key = self.active_session_key orelse return err;
            try self.recoverActiveSessionTransport(session_key);
            return self.openOnce(path, flags);
        };
    }

    fn openOnce(self: *NamespaceClient, path: []const u8, flags: u32) !NamespaceHandle {
        const stat = try self.statPath(path);
        const fid = try self.walkPathToNewFid(path);
        errdefer self.clunk(fid) catch {};
        try self.openFid(fid, if (flagsRequireWrite(flags)) "rw" else "r");
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const handle_id = self.next_handle_id;
        self.next_handle_id +%= 1;
        if (self.next_handle_id == 0) self.next_handle_id = 1;
        try self.open_handles.put(self.allocator, handle_id, .{
            .path = owned_path,
            .flags = flags,
            .fid = fid,
            .writable = stat.writable,
        });
        return .{
            .handle_id = handle_id,
            .writable = stat.writable,
        };
    }

    pub fn read(self: *NamespaceClient, handle: NamespaceHandle, off: u64, len: u32) ![]u8 {
        if (len == 0) return self.allocator.dupe(u8, "");
        const state = try self.resolveOpenHandleForIo(handle.handle_id);
        return self.readFid(state.fid, off, len) catch |err| {
            if (!isTransportError(err)) return err;
            const session_key = self.active_session_key orelse return err;
            try self.recoverActiveSessionTransport(session_key);
            const recovered = try self.resolveOpenHandleForIo(handle.handle_id);
            return self.readFid(recovered.fid, off, len);
        };
    }

    fn readFid(self: *NamespaceClient, fid: u32, off: u64, len: u32) ![]u8 {
        const fields = try std.fmt.allocPrint(
            self.allocator,
            "\"fid\":{d},\"offset\":{d},\"count\":{d}",
            .{ fid, off, len },
        );
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_read, .r_read, fields);
        defer self.allocator.free(payload_json);
        return parseReadPayload(self.allocator, payload_json);
    }

    pub fn write(self: *NamespaceClient, handle: NamespaceHandle, off: u64, data: []const u8) !u32 {
        const state = try self.resolveOpenHandleForIo(handle.handle_id);
        return self.writeFid(state.fid, off, data) catch |err| {
            if (!isTransportError(err)) return err;
            const session_key = self.active_session_key orelse return err;
            try self.recoverActiveSessionTransport(session_key);
            const recovered = try self.resolveOpenHandleForIo(handle.handle_id);
            return self.writeFid(recovered.fid, off, data);
        };
    }

    fn writeFid(self: *NamespaceClient, fid: u32, off: u64, data: []const u8) !u32 {
        const encoded = try encodeBase64(self.allocator, data);
        defer self.allocator.free(encoded);
        const fields = try std.fmt.allocPrint(
            self.allocator,
            "\"fid\":{d},\"offset\":{d},\"data_b64\":\"{s}\"",
            .{ fid, off, encoded },
        );
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_write, .r_write, fields);
        defer self.allocator.free(payload_json);
        return parseWriteCount(self.allocator, payload_json);
    }

    pub fn release(self: *NamespaceClient, handle: NamespaceHandle) !void {
        self.flush() catch {};
        if (self.open_handles.fetchRemove(handle.handle_id)) |removed| {
            var state = removed.value;
            defer state.deinit(self.allocator);
            if (state.fid == 0) return;
            self.clunk(state.fid) catch |err| {
                if (!isTransportError(err)) return err;
            };
        }
    }

    pub fn create(self: *NamespaceClient, path: []const u8, mode: u32, flags: u32) !NamespaceHandle {
        _ = self;
        _ = path;
        _ = mode;
        _ = flags;
        return error.OperationNotSupported;
    }

    pub fn truncate(self: *NamespaceClient, path: []const u8, size: u64) !void {
        _ = self;
        _ = path;
        _ = size;
        return error.OperationNotSupported;
    }

    pub fn unlink(self: *NamespaceClient, path: []const u8) !void {
        _ = self;
        _ = path;
        return error.OperationNotSupported;
    }

    pub fn mkdir(self: *NamespaceClient, path: []const u8) !void {
        _ = self;
        _ = path;
        return error.OperationNotSupported;
    }

    pub fn rmdir(self: *NamespaceClient, path: []const u8) !void {
        _ = self;
        _ = path;
        return error.OperationNotSupported;
    }

    pub fn rename(self: *NamespaceClient, old_path: []const u8, new_path: []const u8) !void {
        _ = self;
        _ = old_path;
        _ = new_path;
        return error.OperationNotSupported;
    }

    pub fn lock(self: *NamespaceClient, handle: NamespaceHandle, mode: []const u8, wait: bool) !void {
        _ = self;
        _ = handle;
        _ = mode;
        _ = wait;
        return error.OperationNotSupported;
    }

    pub fn flush(self: *NamespaceClient) !void {
        const payload_json = try self.callAcheron(.t_flush, .r_flush, "");
        self.allocator.free(payload_json);
    }

    pub fn statPath(self: *NamespaceClient, path: []const u8) !NamespaceStat {
        const fid = try self.walkPathToNewFid(path);
        defer self.clunk(fid) catch {};
        return self.statFid(fid);
    }

    fn statToAttrJson(self: *NamespaceClient, stat: NamespaceStat) ![]u8 {
        const kind_code: u8 = switch (stat.kind) {
            .file => 1,
            .dir => 2,
        };
        const nlink: u32 = switch (stat.kind) {
            .file => 1,
            .dir => 2,
        };
        const owner = currentProcessAttrOwner();
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"k\":{d},\"m\":{d},\"n\":{d},\"u\":{d},\"g\":{d},\"sz\":{d},\"at\":0,\"mt\":0,\"ct\":0,\"gen\":0}}",
            .{ stat.id, kind_code, normalizeMode(stat.mode, stat.kind), nlink, owner.uid, owner.gid, stat.size },
        );
    }

    fn statFid(self: *NamespaceClient, fid: u32) !NamespaceStat {
        const fields = try std.fmt.allocPrint(self.allocator, "\"fid\":{d}", .{fid});
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_stat, .r_stat, fields);
        defer self.allocator.free(payload_json);
        return parseStatPayload(self.allocator, payload_json);
    }

    fn openFid(self: *NamespaceClient, fid: u32, mode: []const u8) !void {
        const escaped_mode = try jsonEscape(self.allocator, mode);
        defer self.allocator.free(escaped_mode);
        const fields = try std.fmt.allocPrint(self.allocator, "\"fid\":{d},\"mode\":\"{s}\"", .{ fid, escaped_mode });
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_open, .r_open, fields);
        self.allocator.free(payload_json);
    }

    fn readAll(self: *NamespaceClient, fid: u32, initial_offset: u64, max_bytes: usize) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        var offset = initial_offset;
        while (out.items.len < max_bytes) {
            const remaining = max_bytes - out.items.len;
            const request_len: u32 = @intCast(@min(remaining, @as(usize, 64 * 1024)));
            const chunk = try self.readFid(fid, offset, request_len);
            defer self.allocator.free(chunk);
            if (chunk.len == 0) break;
            try out.appendSlice(self.allocator, chunk);
            offset += chunk.len;
            if (chunk.len < request_len) break;
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn walkPathToNewFid(self: *NamespaceClient, path: []const u8) !u32 {
        if (!self.namespace_attached) return error.InvalidState;

        const normalized = normalizeAbsolutePath(path);
        var segments = std.ArrayListUnmanaged([]const u8){};
        defer segments.deinit(self.allocator);

        if (!std.mem.eql(u8, normalized, "/")) {
            var it = std.mem.tokenizeScalar(u8, normalized[1..], '/');
            while (it.next()) |segment| {
                if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
                try segments.append(self.allocator, segment);
            }
        }

        const fid = self.next_fid;
        self.next_fid +%= 1;
        if (self.next_fid == 0 or self.next_fid == self.root_fid) self.next_fid = fid + 1;

        const path_json = try encodePathArray(self.allocator, segments.items);
        defer self.allocator.free(path_json);
        const fields = try std.fmt.allocPrint(
            self.allocator,
            "\"fid\":{d},\"newfid\":{d},\"path\":{s}",
            .{ self.root_fid, fid, path_json },
        );
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_walk, .r_walk, fields);
        self.allocator.free(payload_json);
        return fid;
    }

    fn clunk(self: *NamespaceClient, fid: u32) !void {
        const fields = try std.fmt.allocPrint(self.allocator, "\"fid\":{d}", .{fid});
        defer self.allocator.free(fields);
        const payload_json = try self.callAcheron(.t_clunk, .r_clunk, fields);
        self.allocator.free(payload_json);
    }

    fn negotiateControlVersion(self: *NamespaceClient) !void {
        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);
        try self.writeControlRequest("control.version", request_id, "{\"protocol\":\"unified-v2\"}");
        const payload_json = try readControlPayloadFor(self, request_id, "control.version_ack");
        self.allocator.free(payload_json);
    }

    fn controlSessionStatus(self: *NamespaceClient, session_key: []const u8, heartbeat: bool) !SessionStatusInfo {
        const escaped_session = try jsonEscape(self.allocator, session_key);
        defer self.allocator.free(escaped_session);
        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"session_key\":\"{s}\",\"heartbeat\":{s}}}",
            .{ escaped_session, if (heartbeat) "true" else "false" },
        );
        defer self.allocator.free(payload);

        const request_id = try self.nextControlRequestId();
        defer self.allocator.free(request_id);
        try self.writeControlRequest("control.session_status", request_id, payload);
        const payload_json = try readControlPayloadFor(self, request_id, "control.session_status");
        defer self.allocator.free(payload_json);

        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;
        const attach_value = parsed.value.object.get("attach") orelse return error.InvalidResponse;
        if (attach_value != .object) return error.InvalidResponse;
        const state_name = getRequiredString(attach_value.object, "state") orelse return error.InvalidResponse;
        const attach_state: SessionAttachState = if (std.mem.eql(u8, state_name, "warming"))
            .warming
        else if (std.mem.eql(u8, state_name, "ready"))
            .ready
        else if (std.mem.eql(u8, state_name, "error"))
            .err
        else
            return error.InvalidResponse;

        return .{
            .attach_state = attach_state,
            .error_code = try optionalOwnedString(self.allocator, attach_value.object, "error_code"),
        };
    }

    fn waitForSessionReady(self: *NamespaceClient, session_key: []const u8) !void {
        const deadline_ms = std.time.milliTimestamp() + @as(i64, control_reply_timeout_ms);
        while (true) {
            var status = try self.controlSessionStatus(session_key, true);
            defer status.deinit(self.allocator);
            switch (status.attach_state) {
                .ready => return,
                .warming => {},
                .err => {
                    if (status.error_code) |code| return mapRemoteErrorCode(code);
                    return error.RuntimeUnavailable;
                },
            }

            if (std.time.milliTimestamp() >= deadline_ms) return error.TimedOut;
            std.Thread.sleep(session_status_poll_interval_ms * std.time.ns_per_ms);
        }
    }

    fn setActiveSessionKey(self: *NamespaceClient, session_key: []const u8) !void {
        if (self.active_session_key) |value| {
            if (std.mem.eql(u8, value, session_key)) return;
            self.allocator.free(value);
        }
        self.active_session_key = try self.allocator.dupe(u8, session_key);
    }

    fn copySessionKeyForReconnect(self: *NamespaceClient, session_key: []const u8) ![]u8 {
        return try self.allocator.dupe(u8, session_key);
    }

    fn setActiveSessionBinding(
        self: *NamespaceClient,
        agent_id: []const u8,
        project_id: []const u8,
        project_token: ?[]const u8,
    ) !void {
        if (self.active_agent_id) |value| self.allocator.free(value);
        if (self.active_project_id) |value| self.allocator.free(value);
        if (self.active_project_token) |value| self.allocator.free(value);
        self.active_agent_id = try self.allocator.dupe(u8, agent_id);
        self.active_project_id = try self.allocator.dupe(u8, project_id);
        self.active_project_token = if (project_token) |token| try self.allocator.dupe(u8, token) else null;
    }

    fn nextControlRequestId(self: *NamespaceClient) ![]u8 {
        const request_id = try std.fmt.allocPrint(self.allocator, "ns-{d}", .{self.next_control_id});
        self.next_control_id += 1;
        return request_id;
    }

    fn writeControlRequest(self: *NamespaceClient, msg_type: []const u8, request_id: []const u8, payload_json: []const u8) !void {
        const escaped_id = try jsonEscape(self.allocator, request_id);
        defer self.allocator.free(escaped_id);
        const message = try std.fmt.allocPrint(
            self.allocator,
            "{{\"channel\":\"control\",\"type\":\"{s}\",\"id\":\"{s}\",\"payload\":{s}}}",
            .{ msg_type, escaped_id, payload_json },
        );
        defer self.allocator.free(message);
        try writeClientTextFrameMasked(self.allocator, &self.stream, message);
    }

    fn callAcheron(self: *NamespaceClient, request_type: unified.FsrpcType, expected_type: unified.FsrpcType, fields_json: []const u8) ![]u8 {
        while (true) {
            const tag = self.next_tag;
            self.next_tag +%= 1;
            if (self.next_tag == 0) self.next_tag = 1;

            const message = if (fields_json.len == 0)
                try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"channel\":\"acheron\",\"type\":\"{s}\",\"tag\":{d}}}",
                    .{ unified.acheronTypeName(request_type), tag },
                )
            else
                try std.fmt.allocPrint(
                    self.allocator,
                    "{{\"channel\":\"acheron\",\"type\":\"{s}\",\"tag\":{d},{s}}}",
                    .{ unified.acheronTypeName(request_type), tag, fields_json },
                );
            defer self.allocator.free(message);

            try writeClientTextFrameMasked(self.allocator, &self.stream, message);
            return readAcheronPayloadFor(self, tag, expected_type) catch |err| switch (err) {
                error.RuntimeWarming => {
                    const session_key = self.active_session_key orelse return err;
                    self.waitForSessionReady(session_key) catch |wait_err| switch (wait_err) {
                        error.ConnectionClosed,
                        error.ConnectionResetByPeer,
                        error.BrokenPipe,
                        => try self.recoverWarmupTransport(request_type),
                        else => return wait_err,
                    };
                    continue;
                },
                else => return err,
            };
        }
    }

    fn recoverWarmupTransport(self: *NamespaceClient, request_type: unified.FsrpcType) anyerror!void {
        const session_key = self.active_session_key orelse return error.InvalidState;
        const owned_session_key = try self.copySessionKeyForReconnect(session_key);
        defer self.allocator.free(owned_session_key);
        const had_namespace_attached = self.namespace_attached;
        try self.reconnectControlSession(owned_session_key);
        if (!had_namespace_attached) return;
        if (request_type == .t_version or request_type == .t_attach) return;
        try self.attachNamespaceRoot(owned_session_key);
    }

    fn recoverActiveSessionTransport(self: *NamespaceClient, session_key: []const u8) !void {
        const owned_session_key = try self.copySessionKeyForReconnect(session_key);
        defer self.allocator.free(owned_session_key);

        try self.reconnectControlSession(owned_session_key);
        try self.attachNamespaceRoot(owned_session_key);
        try self.reopenAllTrackedHandles();
    }

    fn resolveOpenHandleForIo(self: *NamespaceClient, handle_id: u64) !*OpenHandleState {
        const state = self.open_handles.getPtr(handle_id) orelse return error.InvalidState;
        if (state.fid == 0) return self.reopenTrackedHandle(handle_id);
        return state;
    }

    fn reopenAllTrackedHandles(self: *NamespaceClient) !void {
        var handle_ids = std.ArrayListUnmanaged(u64){};
        defer handle_ids.deinit(self.allocator);

        var it = self.open_handles.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.fid = 0;
            try handle_ids.append(self.allocator, entry.key_ptr.*);
        }
        for (handle_ids.items) |handle_id| {
            _ = self.reopenTrackedHandle(handle_id) catch |err| {
                std.log.warn("namespace reconnect: failed to reopen tracked handle {d}: {s}", .{
                    handle_id,
                    @errorName(err),
                });
                continue;
            };
        }
    }

    fn resolveOpenHandle(self: *NamespaceClient, handle_id: u64) !*OpenHandleState {
        return self.open_handles.getPtr(handle_id) orelse error.InvalidState;
    }

    fn reopenTrackedHandle(self: *NamespaceClient, handle_id: u64) !*OpenHandleState {
        const state = try self.resolveOpenHandle(handle_id);
        const new_fid = try self.walkPathToNewFid(state.path);
        errdefer self.clunk(new_fid) catch {};
        try self.openFid(new_fid, if (flagsRequireWrite(state.flags)) "rw" else "r");
        state.fid = new_fid;
        return state;
    }

    fn reconnectControlSession(self: *NamespaceClient, session_key: []const u8) anyerror!void {
        const agent_id = self.active_agent_id orelse return error.InvalidState;
        const project_id = self.active_project_id orelse return error.InvalidState;
        const previous_stream = self.stream;

        const parsed = try parseWsUrlWithDefaultPath(self.namespace_url, "/");
        var stream = try std.net.tcpConnectToHost(self.allocator, parsed.host, parsed.port);
        var stream_installed = false;
        errdefer if (!stream_installed) stream.close();
        try configureSocketForControl(&stream);

        try performClientHandshake(
            self.allocator,
            &stream,
            parsed.host,
            parsed.port,
            parsed.path,
            self.auth_token,
        );

        self.stream = stream;
        stream_installed = true;
        previous_stream.close();
        self.namespace_attached = false;
        self.next_tag = 1;
        self.next_fid = 2;
        try self.negotiateControlVersion();

        var attach_info = try self.controlSessionAttach(.{
            .session_key = session_key,
            .agent_id = agent_id,
            .project_id = project_id,
            .project_token = self.active_project_token,
        });
        defer attach_info.deinit(self.allocator);
    }
};

const ParsedWsUrl = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

const WsFrame = struct {
    opcode: u8,
    payload: []u8,

    fn deinit(self: *WsFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn parseWsUrlWithDefaultPath(url: []const u8, default_path: []const u8) !ParsedWsUrl {
    const prefix = "ws://";
    if (!std.mem.startsWith(u8, url, prefix)) return error.InvalidUrl;
    const rest = url[prefix.len..];

    const slash_idx = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host_port = rest[0..slash_idx];
    const path = if (slash_idx < rest.len) rest[slash_idx..] else default_path;
    if (host_port.len == 0) return error.InvalidUrl;

    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |colon_idx| {
        const host = host_port[0..colon_idx];
        const port_str = host_port[colon_idx + 1 ..];
        if (host.len == 0 or port_str.len == 0) return error.InvalidUrl;
        return .{
            .host = host,
            .port = try std.fmt.parseInt(u16, port_str, 10),
            .path = path,
        };
    }
    return .{ .host = host_port, .port = 80, .path = path };
}

fn performClientHandshake(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    host: []const u8,
    port: u16,
    path: []const u8,
    auth_token: ?[]const u8,
) !void {
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var encoded_nonce: [std.base64.standard.Encoder.calcSize(nonce.len)]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&encoded_nonce, &nonce);

    const authorization_line = if (auth_token) |token|
        try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}\r\n", .{token})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(authorization_line);

    const request = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "{s}\r\n",
        .{ path, host, port, key, authorization_line },
    );
    defer allocator.free(request);

    try socketWriteAll(stream, request);

    const response = try readHttpResponse(allocator, stream, 8 * 1024);
    defer allocator.free(response);
    if (std.mem.indexOf(u8, response, " 101 ") == null and std.mem.indexOf(u8, response, " 101\r\n") == null) {
        return error.HandshakeRejected;
    }
}

fn readHttpResponse(allocator: std.mem.Allocator, stream: *std.net.Stream, max_bytes: usize) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    const deadline_ms = std.time.milliTimestamp() + @as(i64, control_handshake_timeout_ms);
    var chunk: [512]u8 = undefined;
    while (out.items.len < max_bytes) {
        const now_ms = std.time.milliTimestamp();
        if (now_ms >= deadline_ms) return error.HandshakeTimeout;
        const remaining_i64 = deadline_ms - now_ms;
        const remaining_ms: i32 = @intCast(@min(remaining_i64, @as(i64, std.math.maxInt(i32))));
        if (!try waitReadable(stream, remaining_ms)) return error.HandshakeTimeout;
        const n = try socketRead(stream, &chunk);
        if (n == 0) return error.ConnectionClosed;
        try out.appendSlice(allocator, chunk[0..n]);
        if (std.mem.indexOf(u8, out.items, "\r\n\r\n") != null) {
            return out.toOwnedSlice(allocator);
        }
    }
    return error.ResponseTooLarge;
}

fn readServerFrame(allocator: std.mem.Allocator, stream: *std.net.Stream, max_payload_bytes: usize) !WsFrame {
    var header: [2]u8 = undefined;
    try readExact(stream, &header);

    const fin = (header[0] & 0x80) != 0;
    if (!fin) return error.UnsupportedFragmentation;
    const opcode = header[0] & 0x0F;
    const masked = (header[1] & 0x80) != 0;
    if (masked) return error.UnexpectedMaskedFrame;

    var payload_len: usize = header[1] & 0x7F;
    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        try readExact(stream, &ext);
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        try readExact(stream, &ext);
        payload_len = @intCast(std.mem.readInt(u64, &ext, .big));
    }
    if (payload_len > max_payload_bytes) return error.FrameTooLarge;

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    if (payload_len > 0) try readExact(stream, payload);
    return .{ .opcode = opcode, .payload = payload };
}

fn writeClientTextFrameMasked(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8) !void {
    try writeClientFrameMasked(allocator, stream, payload, 0x1);
}

fn writeClientPongFrameMasked(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8) !void {
    try writeClientFrameMasked(allocator, stream, payload, 0xA);
}

fn writeClientFrameMasked(allocator: std.mem.Allocator, stream: *std.net.Stream, payload: []const u8, opcode: u8) !void {
    var header: [14]u8 = undefined;
    var header_len: usize = 2;
    header[0] = 0x80 | opcode;

    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= std.math.maxInt(u16)) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }

    var mask_key: [4]u8 = undefined;
    std.crypto.random.bytes(&mask_key);
    @memcpy(header[header_len .. header_len + 4], &mask_key);
    header_len += 4;

    const masked_payload = try allocator.alloc(u8, payload.len);
    defer allocator.free(masked_payload);
    for (payload, 0..) |byte, idx| {
        masked_payload[idx] = byte ^ mask_key[idx % 4];
    }

    try socketWriteAll(stream, header[0..header_len]);
    if (masked_payload.len > 0) try socketWriteAll(stream, masked_payload);
}

fn readExact(stream: *std.net.Stream, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = try socketRead(stream, out[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn configureSocketForControl(stream: *std.net.Stream) !void {
    if (builtin.os.tag != .windows) return;

    const windows = std.os.windows;
    const ws2_32 = windows.ws2_32;
    const timeout_ms: windows.DWORD = @intCast(control_reply_timeout_ms);
    const timeout_ptr: [*]const u8 = @ptrCast(&timeout_ms);
    const timeout_len: windows.INT = @intCast(@sizeOf(windows.DWORD));

    if (ws2_32.setsockopt(stream.handle, ws2_32.SOL.SOCKET, ws2_32.SO.RCVTIMEO, timeout_ptr, timeout_len) == ws2_32.SOCKET_ERROR) {
        return windows.unexpectedWSAError(ws2_32.WSAGetLastError());
    }
    if (ws2_32.setsockopt(stream.handle, ws2_32.SOL.SOCKET, ws2_32.SO.SNDTIMEO, timeout_ptr, timeout_len) == ws2_32.SOCKET_ERROR) {
        return windows.unexpectedWSAError(ws2_32.WSAGetLastError());
    }
}

fn socketRead(stream: *std.net.Stream, buffer: []u8) !usize {
    if (builtin.os.tag == .windows) {
        const windows = std.os.windows;
        const ws2_32 = windows.ws2_32;
        const rc = ws2_32.recv(stream.handle, buffer.ptr, @intCast(@min(buffer.len, std.math.maxInt(i32))), 0);
        if (rc == ws2_32.SOCKET_ERROR) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEWOULDBLOCK => error.WouldBlock,
                .WSAETIMEDOUT => error.TimedOut,
                .WSAECONNRESET, .WSAECONNABORTED, .WSAENOTCONN => error.ConnectionResetByPeer,
                else => |err| windows.unexpectedWSAError(err),
            };
        }
        return @intCast(rc);
    }
    return std.posix.recv(stream.handle, buffer, 0);
}

fn socketWriteAll(stream: *std.net.Stream, data: []const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const written: usize = if (builtin.os.tag == .windows) blk: {
            const windows = std.os.windows;
            const ws2_32 = windows.ws2_32;
            const chunk = data[offset..];
            const rc = ws2_32.send(stream.handle, chunk.ptr, @intCast(@min(chunk.len, std.math.maxInt(i32))), 0);
            if (rc == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEWOULDBLOCK => error.WouldBlock,
                    .WSAETIMEDOUT => error.TimedOut,
                    .WSAECONNRESET, .WSAECONNABORTED, .WSAENOTCONN => error.ConnectionResetByPeer,
                    else => |err| windows.unexpectedWSAError(err),
                };
            }
            break :blk @as(usize, @intCast(rc));
        } else try std.posix.send(stream.handle, data[offset..], 0);
        if (written == 0) return error.ConnectionClosed;
        offset += written;
    }
}

fn waitReadable(stream: *std.net.Stream, timeout_ms: i32) !bool {
    if (builtin.os.tag == .windows) {
        const windows = std.os.windows;
        const ws2_32 = windows.ws2_32;
        var fds = [_]ws2_32.WSAPOLLFD{
            .{
                .fd = stream.handle,
                .events = ws2_32.POLL.IN,
                .revents = 0,
            },
        };
        const ready = ws2_32.WSAPoll(&fds, fds.len, timeout_ms);
        if (ready == ws2_32.SOCKET_ERROR) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEWOULDBLOCK, .WSAETIMEDOUT => false,
                .WSAECONNRESET, .WSAECONNABORTED, .WSAENOTCONN => error.ConnectionClosed,
                else => |err| windows.unexpectedWSAError(err),
            };
        }
        if (ready == 0) return false;
        if ((fds[0].revents & (ws2_32.POLL.ERR | ws2_32.POLL.HUP | ws2_32.POLL.NVAL)) != 0) {
            return error.ConnectionClosed;
        }
        return (fds[0].revents & ws2_32.POLL.IN) != 0;
    }

    var fds = [_]std.posix.pollfd{
        .{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        },
    };
    const ready = try std.posix.poll(&fds, timeout_ms);
    if (ready == 0) return false;
    if ((fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
        return error.ConnectionClosed;
    }
    return (fds[0].revents & std.posix.POLL.IN) != 0;
}

fn parseStatPayload(allocator: std.mem.Allocator, payload_json: []const u8) !NamespaceStat {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;

    const id = getRequiredU64(parsed.value.object, "id") orelse return error.InvalidResponse;
    const kind_value = getRequiredString(parsed.value.object, "kind") orelse return error.InvalidResponse;
    const kind: NamespaceStat.Kind = if (std.mem.eql(u8, kind_value, "dir"))
        .dir
    else if (std.mem.eql(u8, kind_value, "file"))
        .file
    else
        return error.InvalidResponse;

    return .{
        .id = id,
        .kind = kind,
        .size = getRequiredU64(parsed.value.object, "size") orelse return error.InvalidResponse,
        .mode = @intCast(getRequiredU64(parsed.value.object, "mode") orelse return error.InvalidResponse),
        .writable = optionalBool(parsed.value.object, "writable") orelse false,
    };
}

fn parseReadPayload(allocator: std.mem.Allocator, payload_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const data_b64 = getRequiredString(parsed.value.object, "data_b64") orelse return error.InvalidResponse;
    return decodeBase64(allocator, data_b64);
}

fn parseWriteCount(allocator: std.mem.Allocator, payload_json: []const u8) !u32 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const n = getRequiredU64(parsed.value.object, "n") orelse return error.InvalidResponse;
    if (n > std.math.maxInt(u32)) return error.InvalidResponse;
    return @intCast(n);
}

fn optionalOwnedString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) !?[]u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return @as(?[]u8, try allocator.dupe(u8, value.string));
}

fn optionalBool(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const value = obj.get(key) orelse return null;
    if (value != .bool) return null;
    return value.bool;
}

fn getRequiredString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn getRequiredU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const value = obj.get(key) orelse return null;
    if (value != .integer or value.integer < 0) return null;
    return @intCast(value.integer);
}

fn getRequiredTag(obj: std.json.ObjectMap) ?u32 {
    const value = obj.get("tag") orelse return null;
    if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32)) return null;
    return @intCast(value.integer);
}

fn encodePathArray(allocator: std.mem.Allocator, segments: []const []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    for (segments, 0..) |segment, idx| {
        if (idx != 0) try out.append(allocator, ',');
        const escaped = try jsonEscape(allocator, segment);
        defer allocator.free(escaped);
        try out.writer(allocator).print("\"{s}\"", .{escaped});
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    for (value) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => if (char < 0x20) {
                try out.writer(allocator).print("\\u00{x:0>2}", .{char});
            } else {
                try out.append(allocator, char);
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, size);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

fn decodeBase64(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const upper_bound = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, upper_bound);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, encoded);
    return out;
}

fn normalizeAbsolutePath(path: []const u8) []const u8 {
    if (path.len == 0) return "/";
    if (path.len > 1 and path[path.len - 1] == '/') return std.mem.trimRight(u8, path, "/");
    return path;
}

fn normalizeMode(mode: u32, kind: NamespaceStat.Kind) u32 {
    if (mode != 0) return mode;
    return switch (kind) {
        .dir => 0o040755,
        .file => 0o100644,
    };
}

fn currentProcessAttrOwner() struct { uid: u32, gid: u32 } {
    return switch (builtin.os.tag) {
        .linux => .{ .uid = @intCast(std.os.linux.getuid()), .gid = @intCast(std.os.linux.getgid()) },
        else => .{ .uid = 0, .gid = 0 },
    };
}

fn flagsRequireWrite(flags: u32) bool {
    return (flags & 0x3) != 0;
}

fn parseConnectInfo(allocator: std.mem.Allocator, payload_json: []const u8) !ConnectInfo {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;

    var info = ConnectInfo{};
    errdefer info.deinit(allocator);
    info.agent_id = try optionalOwnedString(allocator, parsed.value.object, "agent_id");
    info.project_id = try optionalOwnedString(allocator, parsed.value.object, "project_id");
    info.session_key = try optionalOwnedString(allocator, parsed.value.object, "session");
    info.requires_session_attach = optionalBool(parsed.value.object, "requires_session_attach") orelse false;
    if (parsed.value.object.get("workspace")) |workspace_value| {
        info.has_workspace_mounts = workspaceValueHasMounts(workspace_value);
        info.workspace_json = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(workspace_value, .{})});
    }
    return info;
}

fn workspaceValueHasMounts(workspace_value: std.json.Value) bool {
    if (workspace_value != .object) return false;
    const mounts_value = workspace_value.object.get("mounts") orelse return false;
    if (mounts_value != .array) return false;
    return mounts_value.array.items.len > 0;
}

fn readControlPayloadFor(self: *NamespaceClient, expected_id: []const u8, expected_type: []const u8) ![]u8 {
    const deadline_ms = std.time.milliTimestamp() + @as(i64, control_reply_timeout_ms);
    while (true) {
        var parsed = try readMessageUntil(self, deadline_ms);
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;

        const channel = getRequiredString(parsed.value.object, "channel") orelse return error.InvalidResponse;
        if (!std.mem.eql(u8, channel, "control")) continue;

        const id = getRequiredString(parsed.value.object, "id") orelse continue;
        if (!std.mem.eql(u8, id, expected_id)) continue;

        const msg_type = getRequiredString(parsed.value.object, "type") orelse return error.InvalidResponse;
        if (std.mem.eql(u8, msg_type, "control.error")) return mapControlError(parsed.value.object);
        if (!std.mem.eql(u8, msg_type, expected_type)) return error.UnexpectedControlResponse;

        const payload = parsed.value.object.get("payload") orelse return self.allocator.dupe(u8, "{}");
        return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
    }
}

fn readAcheronPayloadFor(self: *NamespaceClient, expected_tag: u32, expected_type: unified.FsrpcType) ![]u8 {
    const deadline_ms = std.time.milliTimestamp() + @as(i64, control_reply_timeout_ms);
    while (true) {
        var parsed = try readMessageUntil(self, deadline_ms);
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidResponse;

        const channel = getRequiredString(parsed.value.object, "channel") orelse return error.InvalidResponse;
        if (!std.mem.eql(u8, channel, "acheron")) continue;

        const tag = getRequiredTag(parsed.value.object) orelse return error.InvalidResponse;
        if (tag != expected_tag) continue;

        const msg_type = getRequiredString(parsed.value.object, "type") orelse return error.InvalidResponse;
        if (std.mem.eql(u8, msg_type, "acheron.error")) return mapAcheronError(parsed.value.object);
        if (!std.mem.eql(u8, msg_type, unified.acheronTypeName(expected_type))) return error.ProtocolError;

        const payload = parsed.value.object.get("payload") orelse return self.allocator.dupe(u8, "{}");
        return std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(payload, .{})});
    }
}

fn readMessageUntil(self: *NamespaceClient, deadline_ms: i64) !std.json.Parsed(std.json.Value) {
    while (true) {
        const now_ms = std.time.milliTimestamp();
        if (now_ms >= deadline_ms) return error.TimedOut;
        const remaining_i64 = deadline_ms - now_ms;
        const remaining_ms: i32 = @intCast(@min(remaining_i64, @as(i64, std.math.maxInt(i32))));
        if (!try waitReadable(&self.stream, remaining_ms)) return error.TimedOut;

        var frame = try readServerFrame(self.allocator, &self.stream, 4 * 1024 * 1024);
        defer frame.deinit(self.allocator);

        switch (frame.opcode) {
            0x1 => return std.json.parseFromSlice(std.json.Value, self.allocator, frame.payload, .{}),
            0x8 => return error.ConnectionClosed,
            0x9 => try writeClientPongFrameMasked(self.allocator, &self.stream, frame.payload),
            0xA => {},
            else => return error.InvalidFrameOpcode,
        }
    }
}

fn mapControlError(root: std.json.ObjectMap) anyerror {
    const err = root.get("error") orelse return error.InvalidResponse;
    if (err != .object) return error.InvalidResponse;
    const code = getRequiredString(err.object, "code") orelse return error.InvalidResponse;
    return mapRemoteErrorCode(code);
}

fn mapAcheronError(root: std.json.ObjectMap) anyerror {
    const err = root.get("error") orelse return error.InvalidResponse;
    if (err != .object) return error.InvalidResponse;
    const code = getRequiredString(err.object, "code") orelse return error.InvalidResponse;
    return mapRemoteErrorCode(code);
}

fn mapRemoteErrorCode(code: []const u8) anyerror {
    if (std.mem.eql(u8, code, "forbidden") or std.mem.eql(u8, code, "access_denied")) return error.PermissionDenied;
    if (std.mem.eql(u8, code, "agent_not_found") or std.mem.eql(u8, code, "project_not_found")) return error.FileNotFound;
    if (std.mem.eql(u8, code, "project_context_required")) return error.ProjectRequired;
    if (std.mem.eql(u8, code, "missing_field")) return error.MissingField;
    if (std.mem.eql(u8, code, "invalid_payload") or std.mem.eql(u8, code, "invalid")) return error.InvalidPayload;
    if (std.mem.eql(u8, code, "enoent")) return error.FileNotFound;
    if (std.mem.eql(u8, code, "eperm")) return error.PermissionDenied;
    if (std.mem.eql(u8, code, "enotdir")) return error.NotDirectory;
    if (std.mem.eql(u8, code, "eisdir")) return error.IsDirectory;
    if (std.mem.eql(u8, code, "eexist")) return error.AlreadyExists;
    if (std.mem.eql(u8, code, "erofs") or std.mem.eql(u8, code, "readonly")) return error.ReadOnlyFilesystem;
    if (std.mem.eql(u8, code, "unsupported")) return error.OperationNotSupported;
    if (std.mem.eql(u8, code, "runtime_warming")) return error.RuntimeWarming;
    if (std.mem.eql(u8, code, "runtime_unavailable")) return error.RuntimeUnavailable;
    if (std.mem.eql(u8, code, "project_mounts_missing")) return error.ProjectMountsMissing;
    if (std.mem.eql(u8, code, "sandbox_mount_unavailable")) return error.SandboxMountUnavailable;
    if (std.mem.eql(u8, code, "sandbox_invalid_config")) return error.InvalidSandboxConfig;
    if (std.mem.eql(u8, code, "runtime_resource_exhausted")) return error.ProcessFdQuotaExceeded;
    if (std.mem.eql(u8, code, "execution_failed")) return error.ExecutionFailed;
    return error.ProtocolError;
}

fn isTransportError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.EndOfStream,
        error.TimedOut,
        => true,
        else => false,
    };
}

test "namespace_client: normalizeAbsolutePath trims trailing separators" {
    try std.testing.expectEqualStrings("/", normalizeAbsolutePath("/"));
    try std.testing.expectEqualStrings("/agents", normalizeAbsolutePath("/agents/"));
    try std.testing.expectEqualStrings("/agents/self", normalizeAbsolutePath("/agents/self"));
}

test "namespace_client: remote payload validation errors stay specific" {
    try std.testing.expect(mapRemoteErrorCode("missing_field") == error.MissingField);
    try std.testing.expect(mapRemoteErrorCode("invalid_payload") == error.InvalidPayload);
    try std.testing.expect(mapRemoteErrorCode("invalid") == error.InvalidPayload);
}

test "namespace_client: stat attrs synthesize mode from kind when remote mode is zero" {
    const allocator = std.testing.allocator;
    const stat = try parseStatPayload(
        allocator,
        "{\"id\":4,\"name\":\"agents\",\"kind\":\"dir\",\"size\":0,\"mode\":0,\"writable\":false}",
    );
    try std.testing.expectEqual(@as(u64, 4), stat.id);
    try std.testing.expectEqual(NamespaceStat.Kind.dir, stat.kind);
    try std.testing.expectEqual(@as(u32, 0o040755), normalizeMode(stat.mode, stat.kind));
}

test "namespace_client: stat attrs use current process owner on posix" {
    if (builtin.os.tag != .linux) return;

    var client: NamespaceClient = undefined;
    client.allocator = std.testing.allocator;
    const attr_json = try client.statToAttrJson(.{
        .id = 7,
        .kind = .file,
        .size = 11,
        .mode = 0o100644,
        .writable = true,
    });
    defer std.testing.allocator.free(attr_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, attr_json, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(@as(i64, std.os.linux.getuid()), parsed.value.object.get("u").?.integer);
    try std.testing.expectEqual(@as(i64, std.os.linux.getgid()), parsed.value.object.get("g").?.integer);
}

test "namespace_client: parseReadPayload decodes data_b64" {
    const allocator = std.testing.allocator;
    const data = try parseReadPayload(allocator, "{\"data_b64\":\"aGVsbG8=\",\"n\":5,\"eof\":true}");
    defer allocator.free(data);
    try std.testing.expectEqualStrings("hello", data);
}

test "namespace_client: parseWriteCount reads n field" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(u32, 7), try parseWriteCount(allocator, "{\"n\":7}"));
}

test "namespace_client: parseConnectInfo preserves workspace payload and mount presence" {
    const allocator = std.testing.allocator;
    var info = try parseConnectInfo(
        allocator,
        "{\"agent_id\":\"agent-a\",\"project_id\":\"proj-a\",\"session\":\"sess-a\",\"requires_session_attach\":true,\"workspace\":{\"mounts\":[{\"mount_path\":\"/nodes/local/fs\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}]}}",
    );
    defer info.deinit(allocator);

    try std.testing.expectEqualStrings("agent-a", info.agent_id.?);
    try std.testing.expectEqualStrings("proj-a", info.project_id.?);
    try std.testing.expectEqualStrings("sess-a", info.session_key.?);
    try std.testing.expect(info.requires_session_attach);
    try std.testing.expect(info.has_workspace_mounts);
    try std.testing.expect(info.workspace_json != null);
    try std.testing.expect(std.mem.indexOf(u8, info.workspace_json.?, "\"mounts\"") != null);
}

test "namespace_client: setActiveSessionKey reuses identical session ids safely" {
    var client: NamespaceClient = undefined;
    client.allocator = std.testing.allocator;
    client.active_session_key = try std.testing.allocator.dupe(u8, "sess-a");
    defer if (client.active_session_key) |value| std.testing.allocator.free(value);

    const before = client.active_session_key.?;
    try client.setActiveSessionKey(before);
    try std.testing.expect(client.active_session_key != null);
    try std.testing.expect(client.active_session_key.?.ptr == before.ptr);
}

test "namespace_client: reconnect session key copy survives active key replacement" {
    var client: NamespaceClient = undefined;
    client.allocator = std.testing.allocator;
    client.active_session_key = try std.testing.allocator.dupe(u8, "sess-a");
    defer if (client.active_session_key) |value| std.testing.allocator.free(value);

    const borrowed = client.active_session_key.?;
    const owned = try client.copySessionKeyForReconnect(borrowed);
    defer std.testing.allocator.free(owned);

    try client.setActiveSessionKey("sess-b");

    try std.testing.expect(owned.ptr != borrowed.ptr);
    try std.testing.expectEqualStrings("sess-a", owned);
}

test "namespace_client: isTransportError recognizes reconnect-worthy failures" {
    try std.testing.expect(isTransportError(error.ConnectionClosed));
    try std.testing.expect(isTransportError(error.ConnectionResetByPeer));
    try std.testing.expect(isTransportError(error.BrokenPipe));
    try std.testing.expect(isTransportError(error.EndOfStream));
    try std.testing.expect(isTransportError(error.TimedOut));
    try std.testing.expect(!isTransportError(error.InvalidResponse));
}
