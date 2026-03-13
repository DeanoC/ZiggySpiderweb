const std = @import("std");
const builtin = @import("builtin");
const unified = @import("spider-protocol").unified;

pub const InvokeOp = enum {
    exec,
    create_session,
    resume_session,
    close_session,
    write_session,
    read_session,
    resize_session,
};

pub const SessionState = struct {
    label: ?[]u8 = null,
    cwd: ?[]u8 = null,
    buffered_result: ?[]u8 = null,
    replay_script: ?[]u8 = null,
    pending_input: ?[]u8 = null,
    created_at_ms: i64 = 0,
    updated_at_ms: i64 = 0,
    last_exec_at_ms: i64 = 0,
    last_read_at_ms: i64 = 0,
    closed_at_ms: i64 = 0,
    exec_count: u64 = 0,
    write_count: u64 = 0,
    read_count: u64 = 0,

    pub fn deinit(self: *SessionState, allocator: std.mem.Allocator) void {
        if (self.label) |value| allocator.free(value);
        if (self.cwd) |value| allocator.free(value);
        if (self.buffered_result) |value| allocator.free(value);
        if (self.replay_script) |value| allocator.free(value);
        if (self.pending_input) |value| allocator.free(value);
        self.* = undefined;
    }

    pub fn isClosed(self: SessionState) bool {
        return self.closed_at_ms != 0;
    }
};

const ExecOutcome = struct {
    output: []u8,
    exit_code: i32 = 0,
    error_message: ?[]u8 = null,

    fn deinit(self: *ExecOutcome, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
        if (self.error_message) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub fn seedNamespace(self: anytype, terminal_dir: u32) !void {
    return seedNamespaceAt(self, terminal_dir, "/global/terminal");
}

pub fn seedNamespaceAt(self: anytype, terminal_dir: u32, base_path: []const u8) !void {
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"terminal-v2\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,RUNTIME.json,PERMISSIONS.json,STATUS.json,status.json,result.json,sessions.json,current.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        terminal_dir,
        "Terminal",
        shape_json,
        "{\"invoke\":true,\"operations\":[\"terminal_session_create\",\"terminal_session_resume\",\"terminal_session_close\",\"terminal_session_write\",\"terminal_session_read\",\"terminal_session_resize\",\"shell_exec\"],\"discoverable\":true,\"interactive\":true,\"sessionized\":true,\"pty\":true}",
        "Sessionized terminal namespace. Create/resume/close PTY sessions and use write/read/resize for interactive workflows.",
    );
    const namespace_mode = self.terminalNamespaceMode();
    const path_model = self.terminalPathModel();
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
        blk: {
            const content = try std.fmt.allocPrint(
                self.allocator,
                "{{\"type\":\"runtime_tool\",\"tool\":\"shell_exec\",\"session_model\":\"terminal-v2\",\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}",
                .{ namespace_mode, path_model },
            );
            defer self.allocator.free(content);
            break :blk content;
        },
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
        blk: {
            const content = try std.fmt.allocPrint(
                self.allocator,
                "{{\"venom_id\":\"terminal-v2\",\"state\":\"namespace\",\"has_invoke\":true,\"sessionized\":true,\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}",
                .{ namespace_mode, path_model },
            );
            defer self.allocator.free(content);
            break :blk content;
        },
        false,
        .none,
    );
    self.terminal_status_id = try self.addFile(
        terminal_dir,
        "status.json",
        blk: {
            const content = try std.fmt.allocPrint(
                self.allocator,
                "{{\"state\":\"idle\",\"tool\":null,\"session_id\":null,\"updated_at_ms\":0,\"error\":null,\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}",
                .{ namespace_mode, path_model },
            );
            defer self.allocator.free(content);
            break :blk content;
        },
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

pub fn handleInvokeWrite(self: anytype, invoke_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(invoke_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const op = invokeOperationFromPayload(obj) orelse return error.InvalidPayload;
    const operation_payload = blk: {
        if (obj.get("arguments")) |value| break :blk try self.renderJsonValue(value);
        if (obj.get("args")) |value| break :blk try self.renderJsonValue(value);
        break :blk try self.allocator.dupe(u8, input);
    };
    defer self.allocator.free(operation_payload);

    return switch (op) {
        .create_session => createSession(self, operation_payload),
        .resume_session => resumeSession(self, operation_payload),
        .close_session => closeSession(self, operation_payload),
        .write_session => writeSession(self, operation_payload),
        .read_session => readSession(self, operation_payload),
        .resize_session => resizeSession(self, operation_payload),
        .exec => execCommand(self, operation_payload),
    };
}

pub fn handleCreateWrite(self: anytype, create_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(create_node_id, payload);
    return createSession(self, payload);
}

pub fn handleResumeWrite(self: anytype, resume_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(resume_node_id, input);
    return resumeSession(self, input);
}

pub fn handleCloseWrite(self: anytype, close_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(close_node_id, payload);
    return closeSession(self, payload);
}

pub fn handleWriteWrite(self: anytype, write_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(write_node_id, input);
    return writeSession(self, input);
}

pub fn handleReadWrite(self: anytype, read_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(read_node_id, payload);
    return readSession(self, payload);
}

pub fn handleResizeWrite(self: anytype, resize_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(resize_node_id, input);
    return resizeSession(self, input);
}

pub fn handleExecWrite(self: anytype, exec_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(exec_node_id, input);
    return execCommand(self, input);
}

pub fn appendShellSingleQuoted(self: anytype, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    try out.append(self.allocator, '\'');
    var start: usize = 0;
    while (start < value.len) {
        if (std.mem.indexOfScalarPos(u8, value, start, '\'')) |idx| {
            if (idx > start) try out.appendSlice(self.allocator, value[start..idx]);
            try out.appendSlice(self.allocator, "'\\''");
            start = idx + 1;
            continue;
        }
        try out.appendSlice(self.allocator, value[start..]);
        break;
    }
    try out.append(self.allocator, '\'');
}

pub fn buildExecArgsJson(self: anytype, obj: std.json.ObjectMap, session_cwd: ?[]const u8) ![]u8 {
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

fn createSession(self: anytype, payload: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const maybe_session_id = try self.sessionJsonObjectOptionalString(obj, "session_id");
    const label = try self.sessionJsonObjectOptionalString(obj, "label");
    const cwd = try self.sessionJsonObjectOptionalString(obj, "cwd");
    _ = try self.sessionJsonObjectOptionalString(obj, "shell");

    const session_id_owned = if (maybe_session_id) |value|
        try self.allocator.dupe(u8, value)
    else
        try generateSessionId(self);
    errdefer self.allocator.free(session_id_owned);
    if (self.terminal_sessions.contains(session_id_owned)) return error.InvalidPayload;

    var session = SessionState{
        .label = if (label) |value| try self.allocator.dupe(u8, value) else null,
        .cwd = if (cwd) |value| try self.allocator.dupe(u8, value) else null,
        .created_at_ms = std.time.milliTimestamp(),
        .updated_at_ms = std.time.milliTimestamp(),
    };
    errdefer session.deinit(self.allocator);

    try self.terminal_sessions.putNoClobber(self.allocator, session_id_owned, session);
    try setCurrentSession(self, session_id_owned);
    try refreshStateFiles(self);
    try updateStatusAndResult(
        self,
        "done",
        "terminal_session_create",
        session_id_owned,
        null,
        "create",
        "{\"state\":\"open\",\"backend\":\"runtime_tool\"}",
    );
    return payload.len;
}

fn resumeSession(self: anytype, payload: []const u8) !usize {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;
    const session_id = (try self.sessionJsonObjectOptionalString(obj, "session_id")) orelse return error.InvalidPayload;
    const session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
    if (session.isClosed()) return error.TerminalSessionClosed;

    session.updated_at_ms = std.time.milliTimestamp();
    try setCurrentSession(self, session_id);
    try refreshStateFiles(self);
    try updateStatusAndResult(self, "done", "terminal_session_resume", session_id, null, "resume", "{\"state\":\"open\"}");
    return payload.len;
}

fn closeSession(self: anytype, payload: []const u8) !usize {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;
    const selected_id = blk: {
        if (try self.sessionJsonObjectOptionalString(obj, "session_id")) |value| break :blk value;
        if (self.current_terminal_session_id) |value| break :blk value;
        break :blk null;
    } orelse return error.InvalidPayload;
    const stable_session_id = try self.allocator.dupe(u8, selected_id);
    defer self.allocator.free(stable_session_id);

    const session = self.terminal_sessions.getPtr(selected_id) orelse return error.TerminalSessionNotFound;
    const now_ms = std.time.milliTimestamp();
    if (session.buffered_result) |old| {
        self.allocator.free(old);
        session.buffered_result = null;
    }
    session.closed_at_ms = now_ms;
    session.updated_at_ms = now_ms;
    if (self.current_terminal_session_id) |current| {
        if (std.mem.eql(u8, current, selected_id)) try setCurrentSession(self, null);
    }
    try refreshStateFiles(self);
    try updateStatusAndResult(self, "done", "terminal_session_close", stable_session_id, null, "close", "{\"state\":\"closed\"}");
    return payload.len;
}

fn writeSession(self: anytype, payload: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const session_id = try resolveSessionIdForPayload(self, obj) orelse return error.InvalidPayload;
    const session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
    if (session.isClosed()) return error.TerminalSessionClosed;

    const write_bytes = try parseWriteBytes(self, obj);
    defer self.allocator.free(write_bytes);
    if (write_bytes.len == 0) return error.InvalidPayload;
    try appendPendingInput(self, session, write_bytes);

    if (hasPendingCommand(session)) {
        var exec_outcome = try executeInput(self, session);
        defer exec_outcome.deinit(self.allocator);
        if (exec_outcome.error_message) |message| {
            session.updated_at_ms = std.time.milliTimestamp();
            try setCurrentSession(self, session_id);
            try refreshStateFiles(self);
            try updateStatusAndResult(self, "failed", "terminal_session_write", session_id, message, "write", "null");
            return payload.len;
        }
        try appendBufferedResult(self, session, exec_outcome.output);
    }

    const now_ms = std.time.milliTimestamp();
    session.updated_at_ms = now_ms;
    session.last_exec_at_ms = now_ms;
    session.write_count +%= 1;
    session.exec_count +%= 1;
    try setCurrentSession(self, session_id);
    try refreshStateFiles(self);

    const write_result = try std.fmt.allocPrint(self.allocator, "{{\"written\":{d}}}", .{write_bytes.len});
    defer self.allocator.free(write_result);
    try updateStatusAndResult(self, "done", "terminal_session_write", session_id, null, "write", write_result);
    return payload.len;
}

fn readSession(self: anytype, payload: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const session_id = try resolveSessionIdForPayload(self, obj) orelse return error.InvalidPayload;
    const session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
    if (session.isClosed()) return error.TerminalSessionClosed;

    const timeout_ms = blk: {
        if (try self.sessionJsonObjectOptionalU64(obj, "timeout_ms")) |value| break :blk @as(i32, @intCast(@min(value, @as(u64, std.math.maxInt(i32)))));
        break :blk @as(i32, 100);
    };
    const max_bytes = blk: {
        if (try self.sessionJsonObjectOptionalU64(obj, "max_bytes")) |value| {
            const clamped = @max(@as(u64, 1), @min(value, @as(u64, 1024 * 1024)));
            break :blk @as(usize, @intCast(clamped));
        }
        break :blk @as(usize, 64 * 1024);
    };

    var remaining_timeout_ms = timeout_ms;
    while (session.buffered_result == null and !hasPendingCommand(session) and remaining_timeout_ms > 0) {
        const wait_ms = @min(remaining_timeout_ms, 25);
        std.Thread.sleep(@as(u64, @intCast(wait_ms)) * std.time.ns_per_ms);
        remaining_timeout_ms -= wait_ms;
    }
    if (session.buffered_result == null and hasPendingCommand(session)) {
        var exec_outcome = try executeInput(self, session);
        defer exec_outcome.deinit(self.allocator);
        if (exec_outcome.error_message) |message| {
            session.updated_at_ms = std.time.milliTimestamp();
            try setCurrentSession(self, session_id);
            try refreshStateFiles(self);
            try updateStatusAndResult(self, "failed", "terminal_session_read", session_id, message, "read", "null");
            return payload.len;
        }
        try appendBufferedResult(self, session, exec_outcome.output);
    }
    const visible_bytes = try consumeBufferedResult(self, session, max_bytes);
    defer self.allocator.free(visible_bytes);

    const now_ms = std.time.milliTimestamp();
    session.updated_at_ms = now_ms;
    session.last_read_at_ms = now_ms;
    session.read_count +%= 1;
    try setCurrentSession(self, session_id);
    try refreshStateFiles(self);

    const read_result = try buildOutputResultJson(self, visible_bytes, false);
    defer self.allocator.free(read_result);
    try updateStatusAndResult(self, "done", "terminal_session_read", session_id, null, "read", read_result);
    return payload.len;
}

fn resizeSession(self: anytype, payload: []const u8) !usize {
    if (builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const cols = (try self.sessionJsonObjectOptionalU64(obj, "cols")) orelse return error.InvalidPayload;
    const rows = (try self.sessionJsonObjectOptionalU64(obj, "rows")) orelse return error.InvalidPayload;
    if (cols == 0 or rows == 0) return error.InvalidPayload;

    const session_id = try resolveSessionIdForPayload(self, obj) orelse return error.InvalidPayload;
    const session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
    if (session.isClosed()) return error.TerminalSessionClosed;

    session.updated_at_ms = std.time.milliTimestamp();
    try setCurrentSession(self, session_id);
    try refreshStateFiles(self);
    const resize_result = try std.fmt.allocPrint(self.allocator, "{{\"cols\":{d},\"rows\":{d}}}", .{ cols, rows });
    defer self.allocator.free(resize_result);
    try updateStatusAndResult(self, "done", "terminal_session_resize", session_id, null, "resize", resize_result);
    return payload.len;
}

fn execCommand(self: anytype, payload: []const u8) !usize {
    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const explicit_session_id = try self.sessionJsonObjectOptionalString(obj, "session_id");
    var selected_session_id: ?[]const u8 = explicit_session_id;
    if (selected_session_id == null) selected_session_id = self.current_terminal_session_id;

    if (selected_session_id) |session_id| {
        const session = self.terminal_sessions.getPtr(session_id) orelse return error.TerminalSessionNotFound;
        if (session.isClosed()) return error.TerminalSessionClosed;
        const stable_session_id = try self.allocator.dupe(u8, session_id);
        defer self.allocator.free(stable_session_id);

        const command_bytes = try buildExecCommandBytes(self, obj);
        defer self.allocator.free(command_bytes);
        var exec_outcome = try executeCommand(self, session, command_bytes);
        defer exec_outcome.deinit(self.allocator);

        const now_ms = std.time.milliTimestamp();
        session.updated_at_ms = now_ms;
        session.last_exec_at_ms = now_ms;
        session.exec_count +%= 1;
        if (try self.sessionJsonObjectOptionalString(obj, "cwd")) |next_cwd| {
            if (session.cwd) |old| self.allocator.free(old);
            session.cwd = try self.allocator.dupe(u8, next_cwd);
        }
        if (exec_outcome.error_message) |message| {
            try setCurrentSession(self, stable_session_id);
            try refreshStateFiles(self);
            try updateStatusAndResult(self, "failed", "shell_exec", stable_session_id, message, "exec", "null");
            return payload.len;
        }
        try setCurrentSession(self, stable_session_id);
        try refreshStateFiles(self);

        const exec_result = try buildExecOutputResultJson(self, exec_outcome.output, false, exec_outcome.exit_code);
        defer self.allocator.free(exec_result);
        try updateStatusAndResult(self, "done", "shell_exec", stable_session_id, null, "exec", exec_result);
        return payload.len;
    }

    var ephemeral_session = SessionState{
        .created_at_ms = std.time.milliTimestamp(),
        .updated_at_ms = std.time.milliTimestamp(),
    };
    defer ephemeral_session.deinit(self.allocator);
    if (try self.sessionJsonObjectOptionalString(obj, "cwd")) |cwd| {
        ephemeral_session.cwd = try self.allocator.dupe(u8, cwd);
    }

    const command_bytes = try buildExecCommandBytes(self, obj);
    defer self.allocator.free(command_bytes);
    var exec_outcome = try executeCommand(self, &ephemeral_session, command_bytes);
    defer exec_outcome.deinit(self.allocator);

    if (exec_outcome.error_message) |message| {
        try updateStatusAndResult(self, "failed", "shell_exec", null, message, "exec", "null");
        return payload.len;
    }

    const exec_result = try buildExecOutputResultJson(self, exec_outcome.output, false, exec_outcome.exit_code);
    defer self.allocator.free(exec_result);
    try updateStatusAndResult(self, "done", "shell_exec", null, null, "exec", exec_result);
    return payload.len;
}

fn appendBufferedResult(self: anytype, session: *SessionState, payload: []const u8) !void {
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

fn appendReplayScript(self: anytype, session: *SessionState, payload: []const u8) !void {
    if (payload.len == 0) return;
    if (session.replay_script) |existing| {
        const merged = try self.allocator.alloc(u8, existing.len + payload.len);
        @memcpy(merged[0..existing.len], existing);
        @memcpy(merged[existing.len..], payload);
        self.allocator.free(existing);
        session.replay_script = merged;
        return;
    }
    session.replay_script = try self.allocator.dupe(u8, payload);
}

fn appendPendingInput(self: anytype, session: *SessionState, payload: []const u8) !void {
    if (payload.len == 0) return;
    if (session.pending_input) |existing| {
        const merged = try self.allocator.alloc(u8, existing.len + payload.len);
        @memcpy(merged[0..existing.len], existing);
        @memcpy(merged[existing.len..], payload);
        self.allocator.free(existing);
        session.pending_input = merged;
        return;
    }
    session.pending_input = try self.allocator.dupe(u8, payload);
}

fn hasPendingCommand(session: *SessionState) bool {
    const pending = session.pending_input orelse return false;
    return pending.len > 0 and pending[pending.len - 1] == '\n';
}

fn executeInput(self: anytype, session: *SessionState) !ExecOutcome {
    const pending = session.pending_input orelse return .{
        .output = try self.allocator.alloc(u8, 0),
        .exit_code = 0,
    };
    defer {
        self.allocator.free(pending);
        session.pending_input = null;
    }
    return executeCommand(self, session, pending);
}

fn executeCommand(self: anytype, session: *SessionState, command_bytes: []const u8) !ExecOutcome {
    const runtime_args = try buildWriteArgsJson(self, session.cwd, session.replay_script, command_bytes);
    defer self.allocator.free(runtime_args);

    const runtime_payload = try self.executeServiceToolCall("shell_exec", runtime_args);
    defer self.allocator.free(runtime_payload);
    if (try self.extractErrorMessageFromToolPayload(runtime_payload)) |message| {
        return .{
            .output = try self.allocator.alloc(u8, 0),
            .error_message = message,
        };
    }
    var shell_result = try self.parseShellExecPayload(runtime_payload);
    defer shell_result.deinit(self.allocator);
    const terminal_output = try self.allocator.alloc(u8, shell_result.stdout.len + shell_result.stderr.len);
    errdefer self.allocator.free(terminal_output);
    @memcpy(terminal_output[0..shell_result.stdout.len], shell_result.stdout);
    @memcpy(terminal_output[shell_result.stdout.len..], shell_result.stderr);
    try appendReplayScript(self, session, command_bytes);
    return .{
        .output = terminal_output,
        .exit_code = shell_result.exit_code,
    };
}

fn buildWriteArgsJson(self: anytype, cwd: ?[]const u8, replay_script: ?[]const u8, write_bytes: []const u8) ![]u8 {
    const shell_command = try buildWriteShellCommand(self, replay_script, write_bytes);
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

fn buildWriteShellCommand(self: anytype, replay_script: ?[]const u8, write_bytes: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    if (replay_script) |history| {
        if (history.len > 0) {
            try out.appendSlice(self.allocator, "{ eval $'");
            try appendAnsiCShellLiteral(self, &out, history);
            try out.appendSlice(self.allocator, "'; } >/dev/null 2>&1\n");
        }
    }
    try out.appendSlice(self.allocator, "eval $'");
    try appendAnsiCShellLiteral(self, &out, write_bytes);
    try out.append(self.allocator, '\'');
    return out.toOwnedSlice(self.allocator);
}

fn appendAnsiCShellLiteral(self: anytype, out: *std.ArrayListUnmanaged(u8), bytes: []const u8) !void {
    for (bytes) |byte| {
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
}

fn buildExecCommandBytes(self: anytype, obj: std.json.ObjectMap) ![]u8 {
    if (try self.sessionJsonObjectOptionalString(obj, "command")) |command| {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, command);
        if (command.len == 0 or command[command.len - 1] != '\n') try buf.append(self.allocator, '\n');
        return buf.toOwnedSlice(self.allocator);
    }
    if (obj.get("argv")) |value| {
        if (value != .array or value.array.items.len == 0) return error.InvalidPayload;
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);
        for (value.array.items, 0..) |item, idx| {
            if (item != .string) return error.InvalidPayload;
            if (idx != 0) try buf.append(self.allocator, ' ');
            try appendShellSingleQuoted(self, &buf, item.string);
        }
        try buf.append(self.allocator, '\n');
        return buf.toOwnedSlice(self.allocator);
    }
    return error.InvalidPayload;
}

fn buildOutputResultJson(self: anytype, output: []const u8, eof: bool) ![]u8 {
    const output_b64 = try unified.encodeDataB64(self.allocator, output);
    defer self.allocator.free(output_b64);
    const escaped_b64 = try unified.jsonEscape(self.allocator, output_b64);
    defer self.allocator.free(escaped_b64);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"n\":{d},\"data_b64\":\"{s}\",\"eof\":{s}}}",
        .{ output.len, escaped_b64, if (eof) "true" else "false" },
    );
}

fn buildExecOutputResultJson(self: anytype, output: []const u8, eof: bool, exit_code: i32) ![]u8 {
    const output_b64 = try unified.encodeDataB64(self.allocator, output);
    defer self.allocator.free(output_b64);
    const escaped_b64 = try unified.jsonEscape(self.allocator, output_b64);
    defer self.allocator.free(escaped_b64);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"n\":{d},\"data_b64\":\"{s}\",\"eof\":{s},\"exit_code\":{d}}}",
        .{ output.len, escaped_b64, if (eof) "true" else "false", exit_code },
    );
}

fn consumeBufferedResult(self: anytype, session: *SessionState, max_bytes: usize) ![]u8 {
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

fn parseWriteBytes(self: anytype, obj: std.json.ObjectMap) ![]u8 {
    const append_newline = (try self.sessionJsonObjectOptionalBool(obj, "append_newline")) orelse false;
    if (try self.sessionJsonObjectOptionalString(obj, "command")) |command| {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, command);
        if (command.len == 0 or command[command.len - 1] != '\n') try buf.append(self.allocator, '\n');
        return buf.toOwnedSlice(self.allocator);
    }
    if (try self.sessionJsonObjectOptionalString(obj, "input")) |input| {
        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, input);
        if (append_newline and (input.len == 0 or input[input.len - 1] != '\n')) try buf.append(self.allocator, '\n');
        return buf.toOwnedSlice(self.allocator);
    }
    if (try self.sessionJsonObjectOptionalString(obj, "data_b64")) |data_b64| {
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

fn resolveSessionIdForPayload(self: anytype, obj: std.json.ObjectMap) !?[]const u8 {
    if (try self.sessionJsonObjectOptionalString(obj, "session_id")) |value| return value;
    if (self.current_terminal_session_id) |value| return value;
    return null;
}

fn invokeOperationFromPayload(obj: std.json.ObjectMap) ?InvokeOp {
    if (obj.get("op")) |value| {
        if (value == .string) return parseInvokeOp(value.string);
    }
    if (obj.get("operation")) |value| {
        if (value == .string) return parseInvokeOp(value.string);
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

fn updateStatusAndResult(
    self: anytype,
    state: []const u8,
    tool_name: []const u8,
    session_id: ?[]const u8,
    error_message: ?[]const u8,
    operation: []const u8,
    result_json: []const u8,
) !void {
    const status = try buildStatusJson(self, state, tool_name, session_id, error_message);
    defer self.allocator.free(status);
    try self.setFileContent(self.terminal_status_id, status);

    const result = try buildResultEnvelope(self, operation, session_id, error_message == null, result_json, error_message);
    defer self.allocator.free(result);
    try self.setFileContent(self.terminal_result_id, result);
}

fn buildStatusJson(
    self: anytype,
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
        "{{\"state\":\"{s}\",\"tool\":\"{s}\",\"session_id\":{s},\"updated_at_ms\":{d},\"error\":{s},\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}",
        .{
            escaped_state,
            escaped_tool,
            session_json,
            std.time.milliTimestamp(),
            error_json,
            self.terminalNamespaceMode(),
            self.terminalPathModel(),
        },
    );
}

fn buildResultEnvelope(
    self: anytype,
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
        .{ if (ok) "true" else "false", escaped_op, session_json, result_json, error_json },
    );
}

fn refreshStateFiles(self: anytype) !void {
    if (self.terminal_sessions_id == 0 or self.terminal_current_id == 0) return;
    const sessions_json = try buildSessionsJson(self);
    defer self.allocator.free(sessions_json);
    try self.setFileContent(self.terminal_sessions_id, sessions_json);

    const current_json = try buildCurrentJson(self);
    defer self.allocator.free(current_json);
    try self.setFileContent(self.terminal_current_id, current_json);
}

fn buildSessionsJson(self: anytype) ![]u8 {
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
            "{{\"session_id\":\"{s}\",\"state\":\"{s}\",\"label\":{s},\"cwd\":{s},\"created_at_ms\":{d},\"updated_at_ms\":{d},\"last_exec_at_ms\":{d},\"closed_at_ms\":{d},\"exec_count\":{d},\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}",
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
                self.terminalNamespaceMode(),
                self.terminalPathModel(),
            },
        );
    }
    try out.appendSlice(self.allocator, "]}");
    return out.toOwnedSlice(self.allocator);
}

fn buildCurrentJson(self: anytype) ![]u8 {
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
        "{{\"session\":{{\"session_id\":\"{s}\",\"state\":\"{s}\",\"cwd\":{s},\"updated_at_ms\":{d},\"namespace_mode\":\"{s}\",\"path_model\":\"{s}\"}}}}",
        .{
            escaped_id,
            escaped_state,
            cwd_json,
            session.updated_at_ms,
            self.terminalNamespaceMode(),
            self.terminalPathModel(),
        },
    );
}

fn setCurrentSession(self: anytype, session_id: ?[]const u8) !void {
    if (self.current_terminal_session_id) |existing| {
        if (session_id) |value| {
            if (std.mem.eql(u8, existing, value)) return;
        }
    } else if (session_id == null) {
        return;
    }

    const next_session_id = if (session_id) |value|
        try self.allocator.dupe(u8, value)
    else
        null;
    errdefer if (next_session_id) |value| self.allocator.free(value);

    if (self.current_terminal_session_id) |existing| self.allocator.free(existing);
    self.current_terminal_session_id = next_session_id;
}

fn generateSessionId(self: anytype) ![]u8 {
    const id = try std.fmt.allocPrint(self.allocator, "term-{d}", .{self.next_terminal_session_seq});
    self.next_terminal_session_seq +%= 1;
    if (self.next_terminal_session_seq == 0) self.next_terminal_session_seq = 1;
    return id;
}

fn parseInvokeOp(raw: []const u8) ?InvokeOp {
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
