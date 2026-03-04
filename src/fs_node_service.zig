const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_ops = @import("fs_node_ops.zig");
const unified = @import("ziggy-spider-protocol").unified;

pub const NodeService = struct {
    pub const ChatInputSubmission = struct {
        job_id: []u8,
        correlation_id: ?[]u8 = null,
        state: fs_node_ops.ChatJobState = .running,
        error_text: ?[]u8 = null,
        result_text: ?[]u8 = null,
        log_text: ?[]u8 = null,

        pub fn deinit(self: *ChatInputSubmission, allocator: std.mem.Allocator) void {
            allocator.free(self.job_id);
            if (self.correlation_id) |value| allocator.free(value);
            if (self.error_text) |value| allocator.free(value);
            if (self.result_text) |value| allocator.free(value);
            if (self.log_text) |value| allocator.free(value);
            self.* = undefined;
        }
    };

    pub const ChatInputHook = struct {
        ctx: ?*anyopaque = null,
        on_submit: *const fn (
            ctx: ?*anyopaque,
            allocator: std.mem.Allocator,
            input: []const u8,
            correlation_id: ?[]const u8,
        ) anyerror!ChatInputSubmission,
    };

    pub const InitOptions = struct {
        chat_input_hook: ?ChatInputHook = null,
    };

    allocator: std.mem.Allocator,
    ops: fs_node_ops.NodeOps,
    chat_input_hook: ?ChatInputHook = null,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, export_specs: []const fs_node_ops.ExportSpec) !NodeService {
        return initWithOptions(allocator, export_specs, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        export_specs: []const fs_node_ops.ExportSpec,
        options: InitOptions,
    ) !NodeService {
        return .{
            .allocator = allocator,
            .ops = try fs_node_ops.NodeOps.init(allocator, export_specs),
            .chat_input_hook = options.chat_input_hook,
        };
    }

    pub fn deinit(self: *NodeService) void {
        self.ops.deinit();
        self.* = undefined;
    }

    pub fn handleRequestJson(self: *NodeService, payload: []const u8) ![]u8 {
        var handled = try self.handleRequestJsonWithEvents(payload);
        defer handled.deinit(self.allocator);
        return self.allocator.dupe(u8, handled.response_json);
    }

    pub const HandledRequest = struct {
        response_json: []u8,
        events: []fs_protocol.InvalidationEvent,

        pub fn deinit(self: *HandledRequest, allocator: std.mem.Allocator) void {
            allocator.free(self.response_json);
            allocator.free(self.events);
            self.* = undefined;
        }
    };

    pub fn handleRequestJsonWithEvents(self: *NodeService, payload: []const u8) !HandledRequest {
        self.mutex.lock();
        defer self.mutex.unlock();

        var parsed = unified.parseMessage(self.allocator, payload) catch |err| {
            return .{
                .response_json = try unified.buildFsrpcFsError(
                    self.allocator,
                    null,
                    fs_protocol.Errno.EINVAL,
                    @errorName(err),
                ),
                .events = try self.allocator.alloc(fs_protocol.InvalidationEvent, 0),
            };
        };
        defer parsed.deinit(self.allocator);

        var req = parseUnifiedFsrpcRequest(self.allocator, parsed) catch |err| {
            return .{
                .response_json = try unified.buildFsrpcFsError(
                    self.allocator,
                    parsed.tag,
                    fs_protocol.Errno.EINVAL,
                    @errorName(err),
                ),
                .events = try self.allocator.alloc(fs_protocol.InvalidationEvent, 0),
            };
        };
        defer req.deinit();

        return self.handleParsedRequestWithEventsUnlocked(req);
    }

    pub fn handleParsedRequest(self: *NodeService, req: fs_protocol.ParsedRequest) ![]u8 {
        var handled = try self.handleParsedRequestWithEvents(req);
        defer handled.deinit(self.allocator);
        return self.allocator.dupe(u8, handled.response_json);
    }

    pub fn handleParsedRequestWithEvents(self: *NodeService, req: fs_protocol.ParsedRequest) !HandledRequest {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.handleParsedRequestWithEventsUnlocked(req);
    }

    pub fn pollFilesystemInvalidations(self: *NodeService, max_events: usize) ![]fs_protocol.InvalidationEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ops.pollFilesystemInvalidations(self.allocator, max_events);
    }

    pub fn copyExportRootPaths(self: *NodeService, allocator: std.mem.Allocator) ![][]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ops.copyExportRootPaths(allocator);
    }

    pub fn upsertNamespaceChatJobWithEvents(
        self: *NodeService,
        update: fs_node_ops.NamespaceChatJobUpdate,
    ) ![]fs_protocol.InvalidationEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.ops.clearPendingEvents();
        try self.ops.upsertNamespaceChatJob(update);
        return self.ops.copyPendingEvents(self.allocator);
    }

    fn handleParsedRequestWithEventsUnlocked(self: *NodeService, req: fs_protocol.ParsedRequest) !HandledRequest {
        var result = self.ops.dispatch(req);
        defer result.deinit(self.allocator);
        if (result.err_no == fs_protocol.Errno.SUCCESS and req.op == .WRITE) {
            self.maybeHandleChatInputWrite(req, &result) catch |err| {
                std.log.warn("fs node chat input submit failed: {s}", .{@errorName(err)});
                if (result.result_json) |value| {
                    self.allocator.free(value);
                    result.result_json = null;
                }
                result.err_no = fs_protocol.Errno.EIO;
                result.err_msg = "chat submit failed";
            };
        }
        const events = try self.ops.copyPendingEvents(self.allocator);
        const response_type = fsrpcResponseType(req.op);

        if (result.err_no == fs_protocol.Errno.SUCCESS) {
            return .{
                .response_json = try unified.buildFsrpcResponse(
                    self.allocator,
                    response_type,
                    req.id,
                    result.result_json orelse "{}",
                ),
                .events = events,
            };
        }

        return .{
            .response_json = try unified.buildFsrpcFsError(
                self.allocator,
                req.id,
                result.err_no,
                result.err_msg,
            ),
            .events = events,
        };
    }

    fn maybeHandleChatInputWrite(
        self: *NodeService,
        req: fs_protocol.ParsedRequest,
        result: *fs_node_ops.DispatchResult,
    ) !void {
        const hook = self.chat_input_hook orelse return;
        const handle_id = req.handle orelse return;
        var snapshot = try self.ops.captureNamespaceWriteSnapshot(self.allocator, handle_id);
        defer if (snapshot) |*value| value.deinit(self.allocator);
        const write_target = snapshot orelse return;
        if (!std.mem.eql(u8, write_target.source_id, "capabilities")) return;
        if (!std.mem.eql(u8, write_target.node_path, "/control/input")) return;

        const input = std.mem.trim(u8, write_target.content, " \t\r\n");
        if (input.len == 0) return;

        const correlation = try std.fmt.allocPrint(self.allocator, "fs-{d}", .{req.id});
        defer self.allocator.free(correlation);

        var submission = try hook.on_submit(hook.ctx, self.allocator, input, correlation);
        defer submission.deinit(self.allocator);

        const effective_correlation = submission.correlation_id orelse correlation;
        try self.ops.upsertNamespaceChatJob(.{
            .job_id = submission.job_id,
            .state = submission.state,
            .correlation_id = effective_correlation,
            .error_text = submission.error_text,
            .result_text = submission.result_text orelse "",
            .log_text = submission.log_text orelse "",
        });

        const write_n = parseWriteResponseCount(result.result_json);
        const augmented = try buildWriteResponseWithChatJob(
            self.allocator,
            write_n,
            submission.job_id,
            effective_correlation,
        );
        if (result.result_json) |value| self.allocator.free(value);
        result.result_json = augmented;
    }
};

pub fn buildInvalidationEventJson(allocator: std.mem.Allocator, event: fs_protocol.InvalidationEvent) ![]u8 {
    return switch (event) {
        .INVAL => |ev| blk: {
            const payload = if (ev.gen) |gen|
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"node\":{d},\"what\":\"{s}\",\"gen\":{d}}}",
                    .{ ev.node, @tagName(ev.what), gen },
                )
            else
                try std.fmt.allocPrint(
                    allocator,
                    "{{\"node\":{d},\"what\":\"{s}\"}}",
                    .{ ev.node, @tagName(ev.what) },
                );
            defer allocator.free(payload);
            break :blk unified.buildFsrpcEvent(allocator, .fs_evt_inval, payload);
        },
        .INVAL_DIR => |ev| blk: {
            const payload = if (ev.dir_gen) |gen|
                try std.fmt.allocPrint(allocator, "{{\"dir\":{d},\"dir_gen\":{d}}}", .{ ev.dir, gen })
            else
                try std.fmt.allocPrint(allocator, "{{\"dir\":{d}}}", .{ev.dir});
            defer allocator.free(payload);
            break :blk unified.buildFsrpcEvent(allocator, .fs_evt_inval_dir, payload);
        },
    };
}

fn parseUnifiedFsrpcRequest(
    allocator: std.mem.Allocator,
    parsed: unified.ParsedMessage,
) !fs_protocol.ParsedRequest {
    const msg_type = parsed.acheron_type orelse return error.UnsupportedType;
    const op = try fsOpFromFsrpcType(msg_type);

    const args_json = parsed.payload_json orelse "{}";
    var args_parsed = try std.json.parseFromSlice(std.json.Value, allocator, args_json, .{});
    errdefer args_parsed.deinit();
    if (args_parsed.value != .object) return error.InvalidPayload;

    return .{
        .parsed = args_parsed,
        .id = parsed.tag orelse 0,
        .op = op,
        .node = parsed.node,
        .handle = parsed.handle,
        .args = args_parsed.value.object,
    };
}

fn fsOpFromFsrpcType(msg_type: unified.FsrpcType) !fs_protocol.Op {
    return switch (msg_type) {
        .fs_t_hello => .HELLO,
        .fs_t_exports => .EXPORTS,
        .fs_t_lookup => .LOOKUP,
        .fs_t_getattr => .GETATTR,
        .fs_t_readdirp => .READDIRP,
        .fs_t_symlink => .SYMLINK,
        .fs_t_setxattr => .SETXATTR,
        .fs_t_getxattr => .GETXATTR,
        .fs_t_listxattr => .LISTXATTR,
        .fs_t_removexattr => .REMOVEXATTR,
        .fs_t_open => .OPEN,
        .fs_t_read => .READ,
        .fs_t_close => .CLOSE,
        .fs_t_lock => .LOCK,
        .fs_t_create => .CREATE,
        .fs_t_write => .WRITE,
        .fs_t_truncate => .TRUNCATE,
        .fs_t_unlink => .UNLINK,
        .fs_t_mkdir => .MKDIR,
        .fs_t_rmdir => .RMDIR,
        .fs_t_rename => .RENAME,
        .fs_t_statfs => .STATFS,
        else => error.UnsupportedType,
    };
}

fn fsrpcResponseType(op: fs_protocol.Op) unified.FsrpcType {
    return switch (op) {
        .HELLO => .fs_r_hello,
        .EXPORTS => .fs_r_exports,
        .LOOKUP => .fs_r_lookup,
        .GETATTR => .fs_r_getattr,
        .READDIRP => .fs_r_readdirp,
        .SYMLINK => .fs_r_symlink,
        .SETXATTR => .fs_r_setxattr,
        .GETXATTR => .fs_r_getxattr,
        .LISTXATTR => .fs_r_listxattr,
        .REMOVEXATTR => .fs_r_removexattr,
        .OPEN => .fs_r_open,
        .READ => .fs_r_read,
        .CLOSE => .fs_r_close,
        .LOCK => .fs_r_lock,
        .CREATE => .fs_r_create,
        .WRITE => .fs_r_write,
        .TRUNCATE => .fs_r_truncate,
        .UNLINK => .fs_r_unlink,
        .MKDIR => .fs_r_mkdir,
        .RMDIR => .fs_r_rmdir,
        .RENAME => .fs_r_rename,
        .STATFS => .fs_r_statfs,
        .INVAL, .INVAL_DIR => .fs_err,
    };
}

fn parseWriteResponseCount(result_json: ?[]const u8) usize {
    const raw = result_json orelse return 0;
    const marker = "\"n\":";
    const marker_idx = std.mem.indexOf(u8, raw, marker) orelse return 0;
    var idx = marker_idx + marker.len;
    while (idx < raw.len and (raw[idx] == ' ' or raw[idx] == '\t')) : (idx += 1) {}

    var count: usize = 0;
    var parsed_any = false;
    while (idx < raw.len and std.ascii.isDigit(raw[idx])) : (idx += 1) {
        parsed_any = true;
        count = std.math.mul(usize, count, 10) catch return 0;
        count = std.math.add(usize, count, @as(usize, raw[idx] - '0')) catch return 0;
    }
    if (!parsed_any) return 0;
    return count;
}

fn buildWriteResponseWithChatJob(
    allocator: std.mem.Allocator,
    written: usize,
    job_id: []const u8,
    correlation_id: []const u8,
) ![]u8 {
    const escaped_job = try unified.jsonEscape(allocator, job_id);
    defer allocator.free(escaped_job);
    const escaped_corr = try unified.jsonEscape(allocator, correlation_id);
    defer allocator.free(escaped_corr);
    return std.fmt.allocPrint(
        allocator,
        "{{\"n\":{d},\"job\":\"{s}\",\"correlation_id\":\"{s}\"}}",
        .{ written, escaped_job, escaped_corr },
    );
}

fn decodeBase64ForTest(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    _ = std.base64.standard.Decoder.decode(decoded, encoded) catch return error.InvalidBase64;
    return decoded;
}

fn testChatInputHook(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    input: []const u8,
    correlation_id: ?[]const u8,
) anyerror!NodeService.ChatInputSubmission {
    _ = raw_ctx;
    if (!std.mem.eql(u8, input, "hello local node")) return error.InvalidPayload;
    return .{
        .job_id = try allocator.dupe(u8, "job-hook-1"),
        .correlation_id = if (correlation_id) |value| try allocator.dupe(u8, value) else null,
        .state = .running,
    };
}

test "fs_node_service: hello request returns success envelope" {
    const allocator = std.testing.allocator;
    var service = try NodeService.init(allocator, &.{});
    defer service.deinit();

    const response = try service.handleRequestJson(
        "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_hello\",\"tag\":1,\"payload\":{}}",
    );
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"ok\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"caps\"") != null);
}

test "fs_node_service: invalid request returns error envelope" {
    const allocator = std.testing.allocator;
    var service = try NodeService.init(allocator, &.{});
    defer service.deinit();

    const response = try service.handleRequestJson(
        "{\"bad\":true}",
    );
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"ok\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"errno\":22") != null);
}

test "fs_node_service: mutating request queues invalidation events" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var service = try NodeService.init(allocator, &[_]fs_node_ops.ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer service.deinit();

    var exports_handled = try service.handleRequestJsonWithEvents(
        "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_exports\",\"tag\":1,\"payload\":{}}",
    );
    defer exports_handled.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_handled.response_json, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("payload").?.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const mkdir_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_mkdir\",\"tag\":2,\"node\":{d},\"payload\":{{\"name\":\"evt-test\"}}}}",
        .{root_id},
    );
    defer allocator.free(mkdir_req);

    var mkdir_handled = try service.handleRequestJsonWithEvents(mkdir_req);
    defer mkdir_handled.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, mkdir_handled.response_json, "\"ok\":true") != null);
    try std.testing.expect(mkdir_handled.events.len >= 1);
    try std.testing.expect(mkdir_handled.events[0] == .INVAL_DIR);
}

test "fs_node_service: pollFilesystemInvalidations detects external changes" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var service = try NodeService.init(allocator, &[_]fs_node_ops.ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer service.deinit();

    const baseline = try service.pollFilesystemInvalidations(256);
    defer allocator.free(baseline);
    try std.testing.expectEqual(@as(usize, 0), baseline.len);

    try tmp_dir.dir.writeFile(.{ .sub_path = "service-external.txt", .data = "123" });
    const changes = try service.pollFilesystemInvalidations(256);
    defer allocator.free(changes);
    try std.testing.expect(changes.len > 0);
}

test "fs_node_service: chat input write invokes hook and populates jobs namespace" {
    const allocator = std.testing.allocator;
    var service = try NodeService.initWithOptions(
        allocator,
        &[_]fs_node_ops.ExportSpec{
            .{
                .name = "chat",
                .path = "chat",
                .source_kind = .namespace,
                .source_id = "capabilities",
                .ro = false,
            },
            .{
                .name = "jobs",
                .path = "jobs",
                .source_kind = .namespace,
                .source_id = "jobs",
                .ro = false,
            },
        },
        .{
            .chat_input_hook = .{
                .ctx = null,
                .on_submit = testChatInputHook,
            },
        },
    );
    defer service.deinit();

    var exports_res = try service.handleRequestJsonWithEvents(
        "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_exports\",\"tag\":1,\"payload\":{}}",
    );
    defer exports_res.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_res.response_json, .{});
    defer exports_parsed.deinit();
    const exports_arr = exports_parsed.value.object.get("payload").?.object.get("exports").?.array.items;

    var chat_root: ?i64 = null;
    var jobs_root: ?i64 = null;
    for (exports_arr) |item| {
        if (item != .object) continue;
        const name = item.object.get("name") orelse continue;
        const root = item.object.get("root") orelse continue;
        if (name != .string or root != .integer) continue;
        if (std.mem.eql(u8, name.string, "chat")) chat_root = root.integer;
        if (std.mem.eql(u8, name.string, "jobs")) jobs_root = root.integer;
    }
    try std.testing.expect(chat_root != null);
    try std.testing.expect(jobs_root != null);

    const control_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":2,\"node\":{d},\"payload\":{{\"name\":\"control\"}}}}",
        .{chat_root.?},
    );
    defer allocator.free(control_lookup_req);
    var control_lookup_res = try service.handleRequestJsonWithEvents(control_lookup_req);
    defer control_lookup_res.deinit(allocator);
    var control_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, control_lookup_res.response_json, .{});
    defer control_lookup_parsed.deinit();
    const control_id = control_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const input_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":3,\"node\":{d},\"payload\":{{\"name\":\"input\"}}}}",
        .{control_id},
    );
    defer allocator.free(input_lookup_req);
    var input_lookup_res = try service.handleRequestJsonWithEvents(input_lookup_req);
    defer input_lookup_res.deinit(allocator);
    var input_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, input_lookup_res.response_json, .{});
    defer input_lookup_parsed.deinit();
    const input_id = input_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const input_open_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":4,\"node\":{d},\"payload\":{{\"flags\":2}}}}",
        .{input_id},
    );
    defer allocator.free(input_open_req);
    var input_open_res = try service.handleRequestJsonWithEvents(input_open_req);
    defer input_open_res.deinit(allocator);
    var input_open_parsed = try std.json.parseFromSlice(std.json.Value, allocator, input_open_res.response_json, .{});
    defer input_open_parsed.deinit();
    const input_handle = input_open_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const payload_b64 = try unified.encodeDataB64(allocator, "hello local node");
    defer allocator.free(payload_b64);
    const input_write_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":5,\"h\":{d},\"payload\":{{\"off\":0,\"data_b64\":\"{s}\"}}}}",
        .{ input_handle, payload_b64 },
    );
    defer allocator.free(input_write_req);
    var input_write_res = try service.handleRequestJsonWithEvents(input_write_req);
    defer input_write_res.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, input_write_res.response_json, "\"job\":\"job-hook-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, input_write_res.response_json, "\"correlation_id\":\"fs-5\"") != null);

    const job_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":6,\"node\":{d},\"payload\":{{\"name\":\"job-hook-1\"}}}}",
        .{jobs_root.?},
    );
    defer allocator.free(job_lookup_req);
    var job_lookup_res = try service.handleRequestJsonWithEvents(job_lookup_req);
    defer job_lookup_res.deinit(allocator);
    var job_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, job_lookup_res.response_json, .{});
    defer job_lookup_parsed.deinit();
    const job_dir_id = job_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const status_lookup_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":7,\"node\":{d},\"payload\":{{\"name\":\"status.json\"}}}}",
        .{job_dir_id},
    );
    defer allocator.free(status_lookup_req);
    var status_lookup_res = try service.handleRequestJsonWithEvents(status_lookup_req);
    defer status_lookup_res.deinit(allocator);
    var status_lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, status_lookup_res.response_json, .{});
    defer status_lookup_parsed.deinit();
    const status_id = status_lookup_parsed.value.object.get("payload").?.object.get("attr").?.object.get("id").?.integer;

    const status_open_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":8,\"node\":{d},\"payload\":{{\"flags\":0}}}}",
        .{status_id},
    );
    defer allocator.free(status_open_req);
    var status_open_res = try service.handleRequestJsonWithEvents(status_open_req);
    defer status_open_res.deinit(allocator);
    var status_open_parsed = try std.json.parseFromSlice(std.json.Value, allocator, status_open_res.response_json, .{});
    defer status_open_parsed.deinit();
    const status_handle = status_open_parsed.value.object.get("payload").?.object.get("h").?.integer;

    const status_read_req = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_read\",\"tag\":9,\"h\":{d},\"payload\":{{\"off\":0,\"len\":8192}}}}",
        .{status_handle},
    );
    defer allocator.free(status_read_req);
    var status_read_res = try service.handleRequestJsonWithEvents(status_read_req);
    defer status_read_res.deinit(allocator);
    var status_read_parsed = try std.json.parseFromSlice(std.json.Value, allocator, status_read_res.response_json, .{});
    defer status_read_parsed.deinit();
    const status_b64 = status_read_parsed.value.object.get("payload").?.object.get("data_b64").?.string;
    const status_json = try decodeBase64ForTest(allocator, status_b64);
    defer allocator.free(status_json);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"correlation_id\":\"fs-5\"") != null);
}
