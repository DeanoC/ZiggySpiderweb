const std = @import("std");
const unified = @import("spider-protocol").unified;
const shared_node = @import("spiderweb_node");
const chat_job_index = @import("../agents/chat_job_index.zig");
const job_projection = @import("../acheron/job_projection.zig");

pub const default_wait_timeout_ms: i64 = 60_000;
pub const wait_poll_interval_ms: u64 = 100;
pub const max_signal_events: usize = 512;

pub const WaitSourceKind = enum {
    chat_input,
    job_status,
    job_result,
    time_after,
    time_at,
    agent_signal,
    hook_signal,
    user_signal,
};

pub const WaitSource = struct {
    raw_path: []u8,
    kind: WaitSourceKind,
    job_id: ?[]u8 = null,
    parameter: ?[]u8 = null,
    target_time_ms: i64 = 0,
    last_seen_updated_at_ms: i64 = 0,
    last_seen_job_event_seq: u64 = 0,
    last_seen_signal_seq: u64 = 0,

    pub fn deinit(self: *WaitSource, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_path);
        if (self.job_id) |value| allocator.free(value);
        if (self.parameter) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const SignalEventType = enum {
    user,
    agent,
    hook,
};

pub const SignalEvent = struct {
    seq: u64,
    event_type: SignalEventType,
    parameter: ?[]u8 = null,
    payload_json: ?[]u8 = null,
    created_at_ms: i64,

    pub fn deinit(self: *SignalEvent, allocator: std.mem.Allocator) void {
        if (self.parameter) |value| allocator.free(value);
        if (self.payload_json) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const WaitCandidate = struct {
    source_index: usize,
    sort_key_ms: i64,
    payload_json: []u8,
    next_last_seen_updated_at_ms: ?i64 = null,
    next_last_seen_job_event_seq: ?u64 = null,
    next_last_seen_signal_seq: ?u64 = null,

    pub fn deinit(self: *WaitCandidate, allocator: std.mem.Allocator) void {
        allocator.free(self.payload_json);
        self.* = undefined;
    }
};

pub fn seedNamespaceAt(self: anytype, events_dir: u32, base_path: []const u8) !void {
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

pub fn clearWaitSources(self: anytype) void {
    for (self.wait_sources.items) |*source| source.deinit(self.allocator);
    self.wait_sources.deinit(self.allocator);
    self.wait_sources = .{};
}

pub fn clearSignalEvents(self: anytype) void {
    for (self.signal_events.items) |*event| event.deinit(self.allocator);
    self.signal_events.deinit(self.allocator);
    self.signal_events = .{};
}

pub fn handleWaitConfigWrite(self: anytype, node_id: u32, raw_input: []const u8) !usize {
    const written = raw_input.len;
    const trimmed = std.mem.trim(u8, raw_input, " \t\r\n");
    if (trimmed.len == 0) {
        clearWaitSources(self);
        self.wait_timeout_ms = default_wait_timeout_ms;
        try self.setFileContent(node_id, "{\"paths\":[],\"timeout_ms\":60000}");
        return written;
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
        var source = try parseWaitSourcePath(self, entry.string);
        try initializeWaitSourceCursor(self, &source);
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

    clearWaitSources(self);
    self.wait_sources = next_sources;
    self.wait_timeout_ms = timeout_ms;
    self.wait_event_seq = 1;

    try self.setFileContent(node_id, trimmed);
    if (self.event_next_id != 0) {
        try self.setFileContent(self.event_next_id, "{\"configured\":true,\"waiting\":false}");
    }
    return written;
}

pub fn handleSignalWrite(self: anytype, node_id: u32, raw_input: []const u8) !usize {
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
    return written;
}

pub fn handleNextRead(self: anytype) ![]u8 {
    if (self.wait_sources.items.len == 0) {
        return self.allocator.dupe(
            u8,
            "{\"configured\":false,\"waiting\":false,\"error\":\"wait_not_configured\"}",
        );
    }

    const timeout_ms = if (self.wait_timeout_ms < 0) default_wait_timeout_ms else self.wait_timeout_ms;
    const start_ms = std.time.milliTimestamp();
    while (true) {
        if (try pollWaitSources(self)) |candidate| {
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

fn parseWaitSourcePath(self: anytype, path: []const u8) !WaitSource {
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
            const parameter = try parseWaitSelectorToken(self, token);
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
            const parameter = try parseWaitSelectorToken(self, token);
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
            const parameter = try parseWaitSelectorToken(self, token);
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
            const delay_ms = try parseWaitSelectorMillis(token);
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
            const target_ms = try parseWaitSelectorMillis(token);
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

fn parseWaitSelectorToken(self: anytype, raw: []const u8) ![]u8 {
    var token = raw;
    if (std.mem.endsWith(u8, token, ".json")) token = token[0 .. token.len - ".json".len];
    if (token.len == 0) return error.InvalidPayload;
    if (std.mem.indexOfScalar(u8, token, '/')) |_| return error.InvalidPayload;
    return self.allocator.dupe(u8, token);
}

fn parseWaitSelectorMillis(raw: []const u8) !i64 {
    var token = raw;
    if (std.mem.endsWith(u8, token, ".json")) token = token[0 .. token.len - ".json".len];
    if (token.len == 0) return error.InvalidPayload;
    const value = std.fmt.parseInt(i64, token, 10) catch return error.InvalidPayload;
    if (value < 0) return error.InvalidPayload;
    return value;
}

fn initializeWaitSourceCursor(self: anytype, source: *WaitSource) !void {
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

fn pollWaitSources(self: anytype) !?WaitCandidate {
    var best: ?WaitCandidate = null;
    errdefer if (best) |*candidate| candidate.deinit(self.allocator);

    for (self.wait_sources.items, 0..) |source, source_index| {
        if (try buildWaitCandidate(self, source, source_index)) |candidate| {
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

fn buildWaitCandidate(self: anytype, source: WaitSource, source_index: usize) !?WaitCandidate {
    return switch (source.kind) {
        .job_status, .job_result => buildJobPathCandidate(self, source, source_index),
        .chat_input => buildChatInputCandidate(self, source, source_index),
        .time_after, .time_at => buildTimeCandidate(self, source, source_index),
        .agent_signal, .hook_signal, .user_signal => buildSignalCandidate(self, source, source_index),
    };
}

fn buildJobPathCandidate(self: anytype, source: WaitSource, source_index: usize) !?WaitCandidate {
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
        nextWaitEventId(self),
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

fn buildChatInputCandidate(self: anytype, source: WaitSource, source_index: usize) !?WaitCandidate {
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
        nextWaitEventId(self),
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

fn buildTimeCandidate(self: anytype, source: WaitSource, source_index: usize) !?WaitCandidate {
    if (source.last_seen_updated_at_ms >= source.target_time_ms) return null;
    const now_ms = std.time.milliTimestamp();
    if (now_ms < source.target_time_ms) return null;
    const payload = try buildTimeWaitEventPayload(self, source.raw_path, source.target_time_ms, now_ms);
    return .{
        .source_index = source_index,
        .sort_key_ms = source.target_time_ms,
        .payload_json = payload,
        .next_last_seen_updated_at_ms = source.target_time_ms,
    };
}

fn buildSignalCandidate(self: anytype, source: WaitSource, source_index: usize) !?WaitCandidate {
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
    const payload = try buildSignalWaitEventPayload(self, source.raw_path, event_path, event.*);
    return .{
        .source_index = source_index,
        .sort_key_ms = event.created_at_ms,
        .payload_json = payload,
        .next_last_seen_signal_seq = event.seq,
    };
}

fn nextWaitEventId(self: anytype) u64 {
    const event_id = self.wait_event_seq;
    self.wait_event_seq +%= 1;
    if (self.wait_event_seq == 0) self.wait_event_seq = 1;
    return event_id;
}

fn buildTimeWaitEventPayload(
    self: anytype,
    source_path: []const u8,
    target_ms: i64,
    now_ms: i64,
) ![]u8 {
    const source_path_escaped = try unified.jsonEscape(self.allocator, source_path);
    defer self.allocator.free(source_path_escaped);
    const event_id = nextWaitEventId(self);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"configured\":true,\"waiting\":false,\"event_id\":{d},\"source_path\":\"{s}\",\"event_path\":\"/nodes/local/venoms/events/sources/time\",\"updated_at_ms\":{d},\"time\":{{\"target_ms\":{d},\"now_ms\":{d},\"fired\":true}}}}",
        .{ event_id, source_path_escaped, now_ms, target_ms, now_ms },
    );
}

fn buildSignalWaitEventPayload(
    self: anytype,
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

    const event_id = nextWaitEventId(self);
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
