const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_ops = @import("fs_node_ops.zig");
const unified = @import("ziggy-spider-protocol").unified;

pub const NodeService = struct {
    allocator: std.mem.Allocator,
    ops: fs_node_ops.NodeOps,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, export_specs: []const fs_node_ops.ExportSpec) !NodeService {
        return .{
            .allocator = allocator,
            .ops = try fs_node_ops.NodeOps.init(allocator, export_specs),
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

    fn handleParsedRequestWithEventsUnlocked(self: *NodeService, req: fs_protocol.ParsedRequest) !HandledRequest {
        var result = self.ops.dispatch(req);
        defer result.deinit(self.allocator);
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
