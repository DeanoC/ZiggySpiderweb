const std = @import("std");
const fs_router = @import("fs_router.zig");
const fs_fuse_adapter = @import("fs_fuse_adapter.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var endpoint_specs = std.ArrayListUnmanaged(fs_router.EndpointConfig){};
    defer endpoint_specs.deinit(allocator);
    var owned_endpoint_fields = std.ArrayListUnmanaged([]u8){};
    defer {
        for (owned_endpoint_fields.items) |value| allocator.free(value);
        owned_endpoint_fields.deinit(allocator);
    }

    var remaining = std.ArrayListUnmanaged([]const u8){};
    defer remaining.deinit(allocator);
    var workspace_url: ?[]const u8 = null;
    var workspace_project_id: ?[]const u8 = null;
    var workspace_project_token: ?[]const u8 = null;
    var workspace_sync_interval_ms: u64 = 5_000;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--endpoint")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            try endpoint_specs.append(allocator, try parseEndpointFlag(args[i]));
        } else if (std.mem.eql(u8, args[i], "--workspace-url")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            workspace_url = args[i];
        } else if (std.mem.eql(u8, args[i], "--workspace-sync-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            workspace_sync_interval_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--project-id")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            workspace_project_id = args[i];
        } else if (std.mem.eql(u8, args[i], "--project-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            workspace_project_token = args[i];
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printHelp();
            return;
        } else {
            try remaining.append(allocator, args[i]);
        }
    }
    if (workspace_project_token != null and workspace_project_id == null) return error.InvalidArguments;

    if (workspace_url) |url| {
        var hydrated = try fetchWorkspaceEndpointSpecs(
            allocator,
            url,
            workspace_project_id,
            workspace_project_token,
        );
        defer hydrated.deinit(allocator);
        for (hydrated.items.items) |item| {
            const owned_name = try allocator.dupe(u8, item.name);
            errdefer allocator.free(owned_name);
            try owned_endpoint_fields.append(allocator, owned_name);

            const owned_url = try allocator.dupe(u8, item.url);
            errdefer allocator.free(owned_url);
            try owned_endpoint_fields.append(allocator, owned_url);

            const owned_mount = try allocator.dupe(u8, item.mount_path);
            errdefer allocator.free(owned_mount);
            try owned_endpoint_fields.append(allocator, owned_mount);

            var owned_export: ?[]u8 = null;
            if (item.export_name) |export_name| {
                owned_export = try allocator.dupe(u8, export_name);
                errdefer allocator.free(owned_export.?);
                try owned_endpoint_fields.append(allocator, owned_export.?);
            }

            var owned_auth: ?[]u8 = null;
            if (item.auth_token) |auth_token| {
                owned_auth = try allocator.dupe(u8, auth_token);
                errdefer allocator.free(owned_auth.?);
                try owned_endpoint_fields.append(allocator, owned_auth.?);
            }

            try endpoint_specs.append(allocator, .{
                .name = owned_name,
                .url = owned_url,
                .export_name = owned_export,
                .mount_path = owned_mount,
                .auth_token = owned_auth,
            });
        }
    }

    if (endpoint_specs.items.len == 0) {
        if (workspace_url != null) {
            std.log.err("no mountable workspace endpoints were returned by control.workspace_status", .{});
            return error.NoWorkspaceMounts;
        }
        try endpoint_specs.append(allocator, .{
            .name = "a",
            .url = "ws://127.0.0.1:18891/v2/fs",
            .export_name = null,
            .mount_path = "/a",
        });
    }
    if (remaining.items.len == 0) {
        try printHelp();
        return error.InvalidArguments;
    }

    var router = try fs_router.Router.init(allocator, endpoint_specs.items);
    defer router.deinit();
    var adapter = fs_fuse_adapter.FuseAdapter.init(allocator, &router);
    defer adapter.deinit();

    const command = remaining.items[0];
    if (std.mem.eql(u8, command, "getattr")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const attr = try adapter.getattr(remaining.items[1]);
        defer allocator.free(attr);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{attr});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "readdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const cookie = if (remaining.items.len >= 3) try std.fmt.parseInt(u64, remaining.items[2], 10) else 0;
        const max_entries = if (remaining.items.len >= 4) try std.fmt.parseInt(u32, remaining.items[3], 10) else 256;
        const listing = try adapter.readdir(remaining.items[1], cookie, max_entries);
        defer allocator.free(listing);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{listing});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "cat")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        const file = try adapter.open(remaining.items[1], 0);
        defer adapter.release(file) catch {};

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);
        var offset: u64 = 0;
        const chunk_len: u32 = 256 * 1024;
        while (true) {
            const chunk = try adapter.read(file, offset, chunk_len);
            defer allocator.free(chunk);
            if (chunk.len == 0) break;
            try out.appendSlice(allocator, chunk);
            if (chunk.len < chunk_len) break;
            offset += chunk.len;
        }
        try std.fs.File.stdout().writeAll(out.items);
        return;
    }

    if (std.mem.eql(u8, command, "write")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        const path = remaining.items[1];
        const content = remaining.items[2];

        const file = adapter.open(path, 2) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            break :blk try adapter.create(path, 0o100644, 2);
        };
        defer adapter.release(file) catch {};

        try adapter.truncate(path, 0);
        _ = try adapter.write(file, 0, content);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "mkdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.mkdir(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "rmdir")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.rmdir(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "unlink")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        try adapter.unlink(remaining.items[1]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "rename")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        try adapter.rename(remaining.items[1], remaining.items[2]);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "truncate")) {
        if (remaining.items.len < 3) return error.InvalidArguments;
        const size = try std.fmt.parseInt(u64, remaining.items[2], 10);
        try adapter.truncate(remaining.items[1], size);
        try std.fs.File.stdout().writeAll("ok\n");
        return;
    }

    if (std.mem.eql(u8, command, "status")) {
        if (remaining.items.len > 2) return error.InvalidArguments;
        var force_probe = true;
        if (remaining.items.len == 2) {
            if (std.mem.eql(u8, remaining.items[1], "--no-probe")) {
                force_probe = false;
            } else {
                return error.InvalidArguments;
            }
        }
        const status = try router.statusJson(force_probe);
        defer allocator.free(status);
        const line = try std.fmt.allocPrint(allocator, "{s}\n", .{status});
        defer allocator.free(line);
        try std.fs.File.stdout().writeAll(line);
        return;
    }

    if (std.mem.eql(u8, command, "mount")) {
        if (remaining.items.len < 2) return error.InvalidArguments;
        var sync_ctx: ?*WorkspaceSyncContext = null;
        var sync_thread: ?std.Thread = null;
        defer {
            if (sync_ctx) |ctx| {
                ctx.requestStop();
                if (sync_thread) |thread| {
                    thread.join();
                }
                ctx.deinit();
                allocator.destroy(ctx);
            }
        }
        if (workspace_url) |url| {
            if (workspace_sync_interval_ms > 0) {
                const ctx = try allocator.create(WorkspaceSyncContext);
                errdefer allocator.destroy(ctx);
                ctx.* = .{
                    .allocator = allocator,
                    .adapter = &adapter,
                    .workspace_url = try allocator.dupe(u8, url),
                    .project_id = if (workspace_project_id) |project_id| try allocator.dupe(u8, project_id) else null,
                    .project_token = if (workspace_project_token) |project_token| try allocator.dupe(u8, project_token) else null,
                    .interval_ms = workspace_sync_interval_ms,
                };
                errdefer allocator.free(ctx.workspace_url);
                errdefer if (ctx.project_id) |project_id| allocator.free(project_id);
                errdefer if (ctx.project_token) |project_token| allocator.free(project_token);
                sync_thread = try std.Thread.spawn(.{}, workspaceSyncThreadMain, .{ctx});
                sync_ctx = ctx;
            }
        }
        try adapter.mount(remaining.items[1]);
        return;
    }

    std.log.err("unknown command: {s}", .{command});
    try printHelp();
    return error.InvalidArguments;
}

fn parseEndpointFlag(raw: []const u8) !fs_router.EndpointConfig {
    const eq_idx = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidEndpointFlag;
    const name = raw[0..eq_idx];
    if (name.len == 0) return error.InvalidEndpointFlag;

    var rhs = raw[eq_idx + 1 ..];
    if (rhs.len == 0) return error.InvalidEndpointFlag;

    var mount_path: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, rhs, '@')) |at_idx| {
        const maybe_mount = rhs[at_idx + 1 ..];
        if (maybe_mount.len > 0 and maybe_mount[0] == '/') {
            mount_path = maybe_mount;
            rhs = rhs[0..at_idx];
        }
    }

    var export_name: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, rhs, '#')) |hash_idx| {
        const maybe_export = rhs[hash_idx + 1 ..];
        if (maybe_export.len == 0) return error.InvalidEndpointFlag;
        export_name = maybe_export;
        rhs = rhs[0..hash_idx];
    }
    const url = rhs;
    if (url.len == 0) return error.InvalidEndpointFlag;

    return .{
        .name = name,
        .url = url,
        .export_name = export_name,
        .mount_path = mount_path,
        .auth_token = null,
    };
}

fn printHelp() !void {
    const help =
        \\spiderweb-fs-mount - Distributed filesystem router client
        \\
        \\Usage:
        \\  spiderweb-fs-mount [--workspace-url <ws-url>] [--project-id <id>] [--project-token <token>] [--workspace-sync-interval-ms <ms>] [--endpoint <name>=<ws-url>[#export][@/mount]] <command> [args]
        \\
        \\Commands:
        \\  getattr <path>
        \\  readdir <path> [cookie] [max]
        \\  cat <path>
        \\  write <path> <content>
        \\  mkdir <path>
        \\  rmdir <path>
        \\  unlink <path>
        \\  rename <old> <new>
        \\  truncate <path> <size>
        \\  status [--no-probe]
        \\  mount <mountpoint>
        \\
        \\Examples:
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work readdir /a
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work@/src readdir /src
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs cat /a/README.md
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs status
        \\  spiderweb-fs-mount --workspace-url ws://127.0.0.1:18790/ readdir /
        \\  spiderweb-fs-mount --workspace-url ws://127.0.0.1:18790/ --workspace-sync-interval-ms 5000 mount /mnt/spiderweb
        \\  spiderweb-fs-mount --endpoint a=ws://127.0.0.1:18891/v2/fs#work@/a --endpoint b=ws://127.0.0.1:18892/v2/fs#work@/a readdir /a
        \\    (repeat the same mount path to enable failover)
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}

const WorkspaceEndpointSpec = struct {
    name: []u8,
    url: []u8,
    export_name: ?[]u8,
    mount_path: []u8,
    auth_token: ?[]u8,

    fn deinit(self: *WorkspaceEndpointSpec, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.url);
        if (self.export_name) |value| allocator.free(value);
        allocator.free(self.mount_path);
        if (self.auth_token) |value| allocator.free(value);
        self.* = undefined;
    }
};

const WorkspaceEndpointSpecs = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayListUnmanaged(WorkspaceEndpointSpec) = .{},

    fn deinit(self: *WorkspaceEndpointSpecs, allocator: std.mem.Allocator) void {
        _ = allocator;
        for (self.items.items) |*item| item.deinit(self.allocator);
        self.items.deinit(self.allocator);
        self.* = undefined;
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

const WorkspaceSyncContext = struct {
    allocator: std.mem.Allocator,
    adapter: *fs_fuse_adapter.FuseAdapter,
    workspace_url: []u8,
    project_id: ?[]u8 = null,
    project_token: ?[]u8 = null,
    interval_ms: u64,
    stop: bool = false,
    stop_mutex: std.Thread.Mutex = .{},
    force_refresh: bool = false,
    force_refresh_mutex: std.Thread.Mutex = .{},

    fn requestStop(self: *WorkspaceSyncContext) void {
        self.stop_mutex.lock();
        self.stop = true;
        self.stop_mutex.unlock();
    }

    fn shouldStop(self: *WorkspaceSyncContext) bool {
        self.stop_mutex.lock();
        defer self.stop_mutex.unlock();
        return self.stop;
    }

    fn deinit(self: *WorkspaceSyncContext) void {
        self.allocator.free(self.workspace_url);
        if (self.project_id) |project_id| self.allocator.free(project_id);
        if (self.project_token) |project_token| self.allocator.free(project_token);
        self.* = undefined;
    }

    fn requestRefresh(self: *WorkspaceSyncContext) void {
        self.force_refresh_mutex.lock();
        self.force_refresh = true;
        self.force_refresh_mutex.unlock();
    }

    fn takeRefreshRequest(self: *WorkspaceSyncContext) bool {
        self.force_refresh_mutex.lock();
        defer self.force_refresh_mutex.unlock();
        const refresh = self.force_refresh;
        self.force_refresh = false;
        return refresh;
    }
};

fn workspaceSyncThreadMain(ctx: *WorkspaceSyncContext) void {
    const allocator = std.heap.page_allocator;
    const push_thread: ?std.Thread = std.Thread.spawn(.{}, workspacePushThreadMain, .{ctx}) catch |err| blk: {
        std.log.warn("workspace sync: push subscription thread disabled: {s}", .{@errorName(err)});
        break :blk null;
    };
    defer if (push_thread) |thread| thread.join();

    ctx.requestRefresh();
    var last_poll_ms: i64 = 0;

    while (true) {
        if (ctx.shouldStop()) return;

        const now_ms = std.time.milliTimestamp();
        const interval_due = ctx.interval_ms > 0 and (last_poll_ms == 0 or now_ms - last_poll_ms >= @as(i64, @intCast(ctx.interval_ms)));
        const should_refresh = ctx.takeRefreshRequest() or interval_due;

        if (should_refresh) {
            tryRefreshWorkspaceTopology(allocator, ctx);
            last_poll_ms = now_ms;
        }

        if (!sleepWithStop(ctx, 250)) return;
    }
}

fn tryRefreshWorkspaceTopology(allocator: std.mem.Allocator, ctx: *WorkspaceSyncContext) void {
    var specs = fetchWorkspaceEndpointSpecs(
        allocator,
        ctx.workspace_url,
        if (ctx.project_id) |project_id| project_id else null,
        if (ctx.project_token) |project_token| project_token else null,
    ) catch |err| {
        std.log.warn("workspace sync: fetch control.workspace_status failed: {s}", .{@errorName(err)});
        return;
    };
    defer specs.deinit(allocator);

    const endpoint_configs = allocator.alloc(fs_router.EndpointConfig, specs.items.items.len) catch |err| {
        std.log.warn("workspace sync: alloc endpoint configs failed: {s}", .{@errorName(err)});
        return;
    };
    defer allocator.free(endpoint_configs);

    for (specs.items.items, 0..) |item, idx| {
        endpoint_configs[idx] = .{
            .name = item.name,
            .url = item.url,
            .export_name = item.export_name,
            .mount_path = item.mount_path,
            .auth_token = item.auth_token,
        };
    }

    _ = ctx.adapter.tryReconcileEndpointsIfIdle(endpoint_configs) catch |err| {
        std.log.warn("workspace sync: reconcile failed: {s}", .{@errorName(err)});
        return;
    };
}

fn workspacePushThreadMain(ctx: *WorkspaceSyncContext) void {
    const allocator = std.heap.page_allocator;
    while (true) {
        if (ctx.shouldStop()) return;

        pumpWorkspacePushSubscription(allocator, ctx) catch |err| {
            std.log.warn("workspace push: subscription loop ended: {s}", .{@errorName(err)});
        };
        if (!sleepWithStop(ctx, 1_000)) return;
    }
}

fn pumpWorkspacePushSubscription(allocator: std.mem.Allocator, ctx: *WorkspaceSyncContext) !void {
    const parsed_url = try parseWsUrlWithDefaultPath(ctx.workspace_url, "/");
    var stream = try std.net.tcpConnectToHost(allocator, parsed_url.host, parsed_url.port);
    defer stream.close();

    try performClientHandshake(allocator, &stream, parsed_url.host, parsed_url.port, parsed_url.path);
    try negotiateControlVersion(allocator, &stream, "fs-mount-push-version");
    try writeClientTextFrameMasked(
        allocator,
        &stream,
        "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"fs-mount-push-connect\"}",
    );
    const connect_payload = try readControlPayloadFor(
        allocator,
        &stream,
        "fs-mount-push-connect",
        "control.connect_ack",
    );
    allocator.free(connect_payload);

    try writeClientTextFrameMasked(
        allocator,
        &stream,
        "{\"channel\":\"control\",\"type\":\"control.debug_subscribe\",\"id\":\"fs-mount-push-subscribe\"}",
    );
    try waitForDebugSubscriptionAck(allocator, &stream, "fs-mount-push-subscribe");

    while (true) {
        if (ctx.shouldStop()) return;
        const ready = try waitReadable(&stream, 500);
        if (!ready) continue;

        var frame = try readServerFrame(allocator, &stream, 4 * 1024 * 1024);
        defer frame.deinit(allocator);
        switch (frame.opcode) {
            0x1 => {
                const applied_delta = applyWorkspaceTopologyDeltaEvent(allocator, ctx, frame.payload) catch |err| blk: {
                    std.log.warn("workspace push: topology delta apply failed: {s}", .{@errorName(err)});
                    ctx.requestRefresh();
                    break :blk false;
                };
                if (applied_delta) continue;

                const is_topology_event = isWorkspaceTopologyEvent(allocator, frame.payload) catch false;
                if (is_topology_event) ctx.requestRefresh();
            },
            0x8 => return error.ConnectionClosed,
            0x9 => try writeClientPongFrameMasked(allocator, &stream, frame.payload),
            0xA => {},
            else => {},
        }
    }
}

fn waitForDebugSubscriptionAck(allocator: std.mem.Allocator, stream: *std.net.Stream, request_id: []const u8) !void {
    while (true) {
        var frame = try readServerFrame(allocator, stream, 4 * 1024 * 1024);
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame.payload, .{});
                defer parsed.deinit();
                if (parsed.value != .object) continue;
                const msg_type = parsed.value.object.get("type") orelse continue;
                if (msg_type != .string) continue;
                if (!std.mem.eql(u8, msg_type.string, "debug.event")) continue;
                const request = parsed.value.object.get("request") orelse continue;
                if (request != .string or !std.mem.eql(u8, request.string, request_id)) continue;
                return;
            },
            0x8 => return error.ConnectionClosed,
            0x9 => try writeClientPongFrameMasked(allocator, stream, frame.payload),
            0xA => {},
            else => return error.InvalidFrameOpcode,
        }
    }
}

fn isWorkspaceTopologyEvent(allocator: std.mem.Allocator, payload: []const u8) !bool {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const msg_type = parsed.value.object.get("type") orelse return false;
    if (msg_type != .string or !std.mem.eql(u8, msg_type.string, "debug.event")) return false;
    const category = parsed.value.object.get("category") orelse return false;
    if (category != .string) return false;
    return std.mem.eql(u8, category.string, "control.workspace_topology");
}

fn applyWorkspaceTopologyDeltaEvent(
    allocator: std.mem.Allocator,
    ctx: *WorkspaceSyncContext,
    frame_payload: []const u8,
) !bool {
    // Delta apply is only safe when the mount client is pinned to a specific project.
    const selected_project = ctx.project_id orelse return false;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame_payload, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const msg_type = parsed.value.object.get("type") orelse return false;
    if (msg_type != .string or !std.mem.eql(u8, msg_type.string, "debug.event")) return false;
    const category = parsed.value.object.get("category") orelse return false;
    if (category != .string or !std.mem.eql(u8, category.string, "control.workspace_topology_delta")) return false;

    const payload = parsed.value.object.get("payload") orelse return error.InvalidWorkspacePayload;
    if (payload != .object) return error.InvalidWorkspacePayload;
    const status = payload.object.get("status") orelse return error.InvalidWorkspacePayload;
    if (status != .object) return error.InvalidWorkspacePayload;

    const project_id = status.object.get("project_id") orelse return error.InvalidWorkspacePayload;
    if (project_id != .string) return true;
    if (!std.mem.eql(u8, project_id.string, selected_project)) return true;

    var specs = WorkspaceEndpointSpecs{ .allocator = allocator };
    defer specs.deinit(allocator);
    try appendWorkspaceMountSpecsFromStatusObject(allocator, &specs, status.object);

    const endpoint_configs = allocator.alloc(fs_router.EndpointConfig, specs.items.items.len) catch return error.OutOfMemory;
    defer allocator.free(endpoint_configs);
    for (specs.items.items, 0..) |item, idx| {
        endpoint_configs[idx] = .{
            .name = item.name,
            .url = item.url,
            .export_name = item.export_name,
            .mount_path = item.mount_path,
            .auth_token = item.auth_token,
        };
    }

    _ = ctx.adapter.tryReconcileEndpointsIfIdle(endpoint_configs) catch return error.ReconcileFailed;
    return true;
}

fn waitReadable(stream: *std.net.Stream, timeout_ms: i32) !bool {
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

fn sleepWithStop(ctx: *WorkspaceSyncContext, total_ms: u64) bool {
    if (total_ms == 0) return !ctx.shouldStop();
    var elapsed: u64 = 0;
    while (elapsed < total_ms) {
        if (ctx.shouldStop()) return false;
        const chunk_ms: u64 = @min(@as(u64, 250), total_ms - elapsed);
        std.Thread.sleep(chunk_ms * std.time.ns_per_ms);
        elapsed += chunk_ms;
    }
    return !ctx.shouldStop();
}

fn fetchWorkspaceEndpointSpecs(
    allocator: std.mem.Allocator,
    workspace_url: []const u8,
    project_id: ?[]const u8,
    project_token: ?[]const u8,
) !WorkspaceEndpointSpecs {
    var specs = WorkspaceEndpointSpecs{ .allocator = allocator };
    errdefer specs.deinit(allocator);

    const parsed_url = try parseWsUrlWithDefaultPath(workspace_url, "/");
    var stream = try std.net.tcpConnectToHost(allocator, parsed_url.host, parsed_url.port);
    defer stream.close();

    try performClientHandshake(allocator, &stream, parsed_url.host, parsed_url.port, parsed_url.path);
    try negotiateControlVersion(allocator, &stream, "fs-mount-version");

    try writeClientTextFrameMasked(
        allocator,
        &stream,
        "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"fs-mount-connect\"}",
    );
    const connect_payload = try readControlPayloadFor(
        allocator,
        &stream,
        "fs-mount-connect",
        "control.connect_ack",
    );
    allocator.free(connect_payload);

    const workspace_request = if (project_id) |selected_project| blk: {
        const escaped_project = try jsonEscape(allocator, selected_project);
        defer allocator.free(escaped_project);
        if (project_token) |token| {
            const escaped_token = try jsonEscape(allocator, token);
            defer allocator.free(escaped_token);
            break :blk try std.fmt.allocPrint(
                allocator,
                "{{\"channel\":\"control\",\"type\":\"control.workspace_status\",\"id\":\"fs-mount-workspace\",\"payload\":{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}}}",
                .{ escaped_project, escaped_token },
            );
        }
        break :blk try std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.workspace_status\",\"id\":\"fs-mount-workspace\",\"payload\":{{\"project_id\":\"{s}\"}}}}",
            .{escaped_project},
        );
    } else try allocator.dupe(u8, "{\"channel\":\"control\",\"type\":\"control.workspace_status\",\"id\":\"fs-mount-workspace\"}");
    defer allocator.free(workspace_request);
    try writeClientTextFrameMasked(allocator, &stream, workspace_request);
    const payload_json = try readControlPayloadFor(
        allocator,
        &stream,
        "fs-mount-workspace",
        "control.workspace_status",
    );
    defer allocator.free(payload_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidWorkspacePayload;
    try appendWorkspaceMountSpecsFromStatusObject(allocator, &specs, parsed.value.object);

    return specs;
}

fn appendWorkspaceMountSpecsFromStatusObject(
    allocator: std.mem.Allocator,
    specs: *WorkspaceEndpointSpecs,
    status_obj: std.json.ObjectMap,
) !void {
    const mounts_value = status_obj.get("mounts") orelse return;
    if (mounts_value != .array) return error.InvalidWorkspacePayload;

    for (mounts_value.array.items) |item| {
        if (item != .object) return error.InvalidWorkspacePayload;
        const mount_path_val = item.object.get("mount_path") orelse return error.InvalidWorkspacePayload;
        if (mount_path_val != .string or mount_path_val.string.len == 0) return error.InvalidWorkspacePayload;

        const url_val = item.object.get("fs_url") orelse continue;
        if (url_val != .string) continue;
        if (url_val.string.len == 0) continue;
        if (!std.mem.startsWith(u8, url_val.string, "ws://")) continue;
        if (std.mem.indexOf(u8, url_val.string, "/v2/fs") == null) continue;

        const node_id = if (item.object.get("node_id")) |value|
            if (value == .string and value.string.len > 0) value.string else "node"
        else
            "node";
        const node_name = if (item.object.get("node_name")) |value|
            if (value == .string and value.string.len > 0) value.string else node_id
        else
            node_id;
        const export_name = if (item.object.get("export_name")) |value|
            if (value == .string and value.string.len > 0) value.string else null
        else
            null;
        const auth_token = if (item.object.get("fs_auth_token")) |value|
            if (value == .string and value.string.len > 0) value.string else null
        else
            null;

        const spec = WorkspaceEndpointSpec{
            .name = try allocator.dupe(u8, node_name),
            .url = try allocator.dupe(u8, url_val.string),
            .export_name = if (export_name) |value| try allocator.dupe(u8, value) else null,
            .mount_path = try allocator.dupe(u8, mount_path_val.string),
            .auth_token = if (auth_token) |value| try allocator.dupe(u8, value) else null,
        };
        try specs.items.append(allocator, spec);
    }
}

fn negotiateControlVersion(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    request_id: []const u8,
) !void {
    const message = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"{s}\",\"payload\":{{\"protocol\":\"unified-v2\"}}}}",
        .{request_id},
    );
    defer allocator.free(message);
    try writeClientTextFrameMasked(allocator, stream, message);
    const payload = try readControlPayloadFor(allocator, stream, request_id, "control.version_ack");
    allocator.free(payload);
}

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
        const port = try std.fmt.parseInt(u16, port_str, 10);
        return .{ .host = host, .port = port, .path = path };
    }
    return .{ .host = host_port, .port = 80, .path = path };
}

fn performClientHandshake(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    host: []const u8,
    port: u16,
    path: []const u8,
) !void {
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var encoded_nonce: [std.base64.standard.Encoder.calcSize(nonce.len)]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&encoded_nonce, &nonce);

    const request = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}:{d}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n\r\n",
        .{ path, host, port, key },
    );
    defer allocator.free(request);

    try stream.writeAll(request);

    const response = try readHttpResponse(allocator, stream, 8 * 1024);
    defer allocator.free(response);
    if (std.mem.indexOf(u8, response, " 101 ") == null and std.mem.indexOf(u8, response, " 101\r\n") == null) {
        return error.HandshakeRejected;
    }
}

fn readHttpResponse(allocator: std.mem.Allocator, stream: *std.net.Stream, max_bytes: usize) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    var chunk: [512]u8 = undefined;
    while (out.items.len < max_bytes) {
        const n = try stream.read(&chunk);
        if (n == 0) return error.ConnectionClosed;
        try out.appendSlice(allocator, chunk[0..n]);
        if (std.mem.indexOf(u8, out.items, "\r\n\r\n") != null) {
            return out.toOwnedSlice(allocator);
        }
    }
    return error.ResponseTooLarge;
}

fn readControlPayloadFor(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    expected_id: []const u8,
    expected_type: []const u8,
) ![]u8 {
    while (true) {
        var frame = try readServerFrame(allocator, stream, 4 * 1024 * 1024);
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame.payload, .{});
                defer parsed.deinit();
                if (parsed.value != .object) continue;
                const root = parsed.value.object;

                const channel = root.get("channel") orelse continue;
                if (channel != .string or !std.mem.eql(u8, channel.string, "control")) continue;

                const msg_id = root.get("id") orelse continue;
                if (msg_id != .string or !std.mem.eql(u8, msg_id.string, expected_id)) continue;

                const msg_type = root.get("type") orelse continue;
                if (msg_type != .string) continue;
                if (std.mem.eql(u8, msg_type.string, "control.error")) {
                    return error.ControlRequestFailed;
                }
                if (!std.mem.eql(u8, msg_type.string, expected_type)) {
                    return error.UnexpectedControlResponse;
                }

                const payload = root.get("payload") orelse return allocator.dupe(u8, "{}");
                return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(payload, .{})});
            },
            0x8 => return error.ConnectionClosed,
            0x9 => try writeClientPongFrameMasked(allocator, stream, frame.payload),
            0xA => {},
            else => return error.InvalidFrameOpcode,
        }
    }
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

    try stream.writeAll(header[0..header_len]);
    if (masked_payload.len > 0) try stream.writeAll(masked_payload);
}

fn readExact(stream: *std.net.Stream, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = try stream.read(out[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
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

test "fs_mount_main: parseEndpointFlag supports explicit mount path" {
    const parsed = try parseEndpointFlag("a=ws://127.0.0.1:18891/v2/fs#work@/src");
    try std.testing.expectEqualStrings("a", parsed.name);
    try std.testing.expectEqualStrings("ws://127.0.0.1:18891/v2/fs", parsed.url);
    try std.testing.expectEqualStrings("work", parsed.export_name.?);
    try std.testing.expectEqualStrings("/src", parsed.mount_path.?);
}

test "fs_mount_main: parseEndpointFlag defaults mount path to endpoint name" {
    const parsed = try parseEndpointFlag("alpha=ws://127.0.0.1:18891/v2/fs#work");
    try std.testing.expectEqualStrings("alpha", parsed.name);
    try std.testing.expectEqualStrings("ws://127.0.0.1:18891/v2/fs", parsed.url);
    try std.testing.expectEqualStrings("work", parsed.export_name.?);
    try std.testing.expect(parsed.mount_path == null);
}
