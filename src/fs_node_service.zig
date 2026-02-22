const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");
const fs_node_ops = @import("fs_node_ops.zig");

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

        var req = fs_protocol.parseRequest(self.allocator, payload) catch |err| {
            return .{
                .response_json = try fs_protocol.buildErrorResponse(
                    self.allocator,
                    0,
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

        if (result.err_no == fs_protocol.Errno.SUCCESS) {
            return .{
                .response_json = try fs_protocol.buildSuccessResponse(
                    self.allocator,
                    req.id,
                    result.result_json orelse "{}",
                ),
                .events = events,
            };
        }

        return .{
            .response_json = try fs_protocol.buildErrorResponse(
                self.allocator,
                req.id,
                result.err_no,
                result.err_msg,
            ),
            .events = events,
        };
    }
};

test "fs_node_service: hello request returns success envelope" {
    const allocator = std.testing.allocator;
    var service = try NodeService.init(allocator, &.{});
    defer service.deinit();

    const response = try service.handleRequestJson(
        "{\"t\":\"req\",\"id\":1,\"op\":\"HELLO\",\"a\":{}}",
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
    try std.testing.expect(std.mem.indexOf(u8, response, "\"no\":22") != null);
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
        "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\",\"a\":{}}",
    );
    defer exports_handled.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_handled.response_json, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("r").?.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const mkdir_req = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"MKDIR\",\"node\":{d},\"a\":{{\"name\":\"evt-test\"}}}}",
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
