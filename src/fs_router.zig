const std = @import("std");
const fs_protocol = @import("fs_protocol.zig");
const fs_client = @import("fs_client.zig");
const fs_cache = @import("fs_cache.zig");
const fs_source_policy = @import("fs_source_policy.zig");
const fsrpc_node_protocol_version = "unified-v2-fs";
const fsrpc_node_proto_id: i64 = 2;

const RouterError = error{
    InvalidPath,
    UnknownEndpoint,
    EndpointUnavailable,
    FileNotFound,
    PermissionDenied,
    NotDirectory,
    IsDirectory,
    AlreadyExists,
    NoData,
    NoSpace,
    Range,
    WouldBlock,
    CrossEndpointRename,
    ReadOnlyFilesystem,
    OperationNotSupported,
    InvalidResponse,
    IOError,
    ProtocolError,
};

pub const EndpointConfig = struct {
    name: []const u8,
    url: []const u8,
    export_name: ?[]const u8 = null,
    mount_path: ?[]const u8 = null,
    auth_token: ?[]const u8 = null,
};

pub const LockMode = enum {
    shared,
    exclusive,
    unlock,
};

const Endpoint = struct {
    name: []u8,
    url: []u8,
    export_name: ?[]u8,
    mount_path: []u8,
    auth_token: ?[]u8 = null,
    root_node_id: u64,
    export_read_only: ?bool = null,
    source_kind: ?[]u8 = null,
    source_id: ?[]u8 = null,
    caps_native_watch: ?bool = null,
    caps_case_sensitive: ?bool = null,
    client: ?fs_client.FsClient = null,
    event_client: ?fs_client.FsClient = null,
    event_thread: ?std.Thread = null,
    event_stop: bool = false,
    event_mutex: std.Thread.Mutex = .{},
    healthy: bool = true,
    last_health_check_ms: i64 = 0,
    last_success_ms: i64 = 0,
    last_failure_ms: i64 = 0,
    consecutive_failures: u32 = 0,

    fn deinit(self: *Endpoint, allocator: std.mem.Allocator) void {
        if (self.client) |*client| client.deinit();
        if (self.event_client) |*client| client.deinit();
        allocator.free(self.name);
        allocator.free(self.url);
        if (self.export_name) |value| allocator.free(value);
        allocator.free(self.mount_path);
        if (self.auth_token) |value| allocator.free(value);
        self.clearExportMetadata(allocator);
        self.* = undefined;
    }

    fn clearExportMetadata(self: *Endpoint, allocator: std.mem.Allocator) void {
        if (self.source_kind) |value| allocator.free(value);
        if (self.source_id) |value| allocator.free(value);
        self.export_read_only = null;
        self.source_kind = null;
        self.source_id = null;
        self.caps_native_watch = null;
        self.caps_case_sensitive = null;
    }
};

const SelectedExport = struct {
    root_id: u64,
    read_only: ?bool = null,
    source_kind: ?[]u8 = null,
    source_id: ?[]u8 = null,
    native_watch: ?bool = null,
    case_sensitive: ?bool = null,

    fn deinit(self: *SelectedExport, allocator: std.mem.Allocator) void {
        if (self.source_kind) |value| allocator.free(value);
        if (self.source_id) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const OpenFile = struct {
    endpoint_index: u16,
    handle_id: u64,
    node_id: u64,
    readable: bool,
    writable: bool,
};

const ResolvedNode = struct {
    endpoint_index: u16,
    node_id: u64,
    parent_id: ?u64,
    name: ?[]const u8,
};

const PathCandidate = struct {
    endpoint_index: usize,
    relative_path: []const u8,
};

const PendingInvalidation = struct {
    endpoint_index: u16,
    event: fs_protocol.InvalidationEvent,
};

pub const Router = struct {
    allocator: std.mem.Allocator,
    endpoints: std.ArrayListUnmanaged(Endpoint) = .{},
    attr_cache: fs_cache.AttrCache,
    dir_cache: fs_cache.DirEntryCache,
    dir_listing_cache: fs_cache.DirListingCache,
    dir_complete_cache: fs_cache.DirCompleteCache,
    dir_prime_cache: fs_cache.DirCompleteCache,
    negative_cache: fs_cache.NegativeCache,
    read_cache: fs_cache.ReadBlockCache,
    pending_invalidations: std.ArrayListUnmanaged(PendingInvalidation) = .{},
    pending_invalidations_mutex: std.Thread.Mutex = .{},
    event_pumps_armed: bool = false,
    block_size: u32 = 256 * 1024,
    health_check_interval_ms: i64 = 2_000,
    unhealthy_retry_interval_ms: i64 = 1_500,
    failover_events_total: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, endpoint_configs: []const EndpointConfig) !Router {
        var router = Router{
            .allocator = allocator,
            .attr_cache = fs_cache.AttrCache.init(allocator, 300_000),
            .dir_cache = fs_cache.DirEntryCache.init(allocator, 300_000),
            .dir_listing_cache = fs_cache.DirListingCache.init(allocator, 300_000),
            .dir_complete_cache = fs_cache.DirCompleteCache.init(allocator, 300_000),
            .dir_prime_cache = fs_cache.DirCompleteCache.init(allocator, 30_000),
            .negative_cache = fs_cache.NegativeCache.init(allocator, 15_000),
            .read_cache = fs_cache.ReadBlockCache.init(allocator, 256),
        };
        errdefer router.deinit();

        for (endpoint_configs) |cfg| try router.addEndpoint(cfg);
        return router;
    }

    pub fn reconcileEndpoints(self: *Router, endpoint_configs: []const EndpointConfig) !void {
        if (self.topologyMatches(endpoint_configs)) return;
        try self.replaceEndpoints(endpoint_configs);
    }

    pub fn replaceEndpoints(self: *Router, endpoint_configs: []const EndpointConfig) !void {
        const attr_ttl = self.attr_cache.ttl_ms;
        const dir_ttl = self.dir_cache.ttl_ms;
        const dir_listing_ttl = self.dir_listing_cache.ttl_ms;
        const dir_complete_ttl = self.dir_complete_cache.ttl_ms;
        const dir_prime_ttl = self.dir_prime_cache.ttl_ms;
        const negative_ttl = self.negative_cache.ttl_ms;
        const read_capacity = self.read_cache.capacity_blocks;

        self.clearEndpoints();
        self.clearPendingInvalidations();

        self.attr_cache.deinit();
        self.dir_cache.deinit();
        self.dir_listing_cache.deinit();
        self.dir_complete_cache.deinit();
        self.dir_prime_cache.deinit();
        self.negative_cache.deinit();
        self.read_cache.deinit();
        self.attr_cache = fs_cache.AttrCache.init(self.allocator, attr_ttl);
        self.dir_cache = fs_cache.DirEntryCache.init(self.allocator, dir_ttl);
        self.dir_listing_cache = fs_cache.DirListingCache.init(self.allocator, dir_listing_ttl);
        self.dir_complete_cache = fs_cache.DirCompleteCache.init(self.allocator, dir_complete_ttl);
        self.dir_prime_cache = fs_cache.DirCompleteCache.init(self.allocator, dir_prime_ttl);
        self.negative_cache = fs_cache.NegativeCache.init(self.allocator, negative_ttl);
        self.read_cache = fs_cache.ReadBlockCache.init(self.allocator, read_capacity);

        for (endpoint_configs) |cfg| try self.addEndpoint(cfg);
    }

    fn topologyMatches(self: *const Router, endpoint_configs: []const EndpointConfig) bool {
        if (self.endpoints.items.len != endpoint_configs.len) return false;

        for (self.endpoints.items, endpoint_configs) |endpoint, cfg| {
            if (!std.mem.eql(u8, endpoint.name, cfg.name)) return false;
            if (!std.mem.eql(u8, endpoint.url, cfg.url)) return false;
            const mount_seed = if (cfg.mount_path) |path|
                path
            else
                std.fmt.allocPrint(self.allocator, "/{s}", .{cfg.name}) catch return false;
            defer if (cfg.mount_path == null) self.allocator.free(mount_seed);
            const normalized_cfg = normalizeMountPath(self.allocator, mount_seed) catch return false;
            defer self.allocator.free(normalized_cfg);
            if (!std.mem.eql(u8, endpoint.mount_path, normalized_cfg)) return false;

            const endpoint_export = endpoint.export_name;
            const cfg_export = cfg.export_name;
            if (!optionalSliceEql(endpoint_export, cfg_export)) return false;

            const endpoint_auth = endpoint.auth_token;
            const cfg_auth = cfg.auth_token;
            if (!optionalSliceEql(endpoint_auth, cfg_auth)) return false;
        }
        return true;
    }

    pub fn deinit(self: *Router) void {
        self.clearEndpoints();
        self.endpoints.deinit(self.allocator);
        self.clearPendingInvalidations();
        self.pending_invalidations.deinit(self.allocator);
        self.attr_cache.deinit();
        self.dir_cache.deinit();
        self.dir_listing_cache.deinit();
        self.dir_complete_cache.deinit();
        self.dir_prime_cache.deinit();
        self.negative_cache.deinit();
        self.read_cache.deinit();
    }

    pub fn endpointNames(self: *const Router) []const Endpoint {
        return self.endpoints.items;
    }

    pub fn endpointCount(self: *const Router) usize {
        return self.endpoints.items.len;
    }

    pub fn endpointName(self: *const Router, index: usize) ?[]const u8 {
        if (index >= self.endpoints.items.len) return null;
        return self.endpoints.items[index].name;
    }

    pub fn endpointMountPath(self: *const Router, index: usize) ?[]const u8 {
        if (index >= self.endpoints.items.len) return null;
        return self.endpoints.items[index].mount_path;
    }

    pub fn statusJson(self: *Router, force_probe: bool) ![]u8 {
        self.drainPendingInvalidations();
        if (force_probe) {
            for (self.endpoints.items, 0..) |_, endpoint_index| {
                self.refreshEndpointHealth(endpoint_index, true) catch {
                    self.noteEndpointFailure(endpoint_index);
                };
            }
        }

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.writer(self.allocator).print(
            "{{\"metrics\":{{\"failover_events_total\":{d}}},\"endpoints\":[",
            .{self.failover_events_total},
        );

        for (self.endpoints.items, 0..) |endpoint, endpoint_index| {
            if (endpoint_index != 0) try out.append(self.allocator, ',');

            const escaped_name = try fs_protocol.jsonEscape(self.allocator, endpoint.name);
            defer self.allocator.free(escaped_name);
            const escaped_url = try fs_protocol.jsonEscape(self.allocator, endpoint.url);
            defer self.allocator.free(escaped_url);
            const escaped_export = try fs_protocol.jsonEscape(self.allocator, endpoint.export_name orelse "");
            defer self.allocator.free(escaped_export);
            const escaped_mount = try fs_protocol.jsonEscape(self.allocator, endpoint.mount_path);
            defer self.allocator.free(escaped_mount);
            const source_kind_json = if (endpoint.source_kind) |value| blk: {
                const escaped = try fs_protocol.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(source_kind_json);
            const source_id_json = if (endpoint.source_id) |value| blk: {
                const escaped = try fs_protocol.jsonEscape(self.allocator, value);
                defer self.allocator.free(escaped);
                break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
            } else try self.allocator.dupe(u8, "null");
            defer self.allocator.free(source_id_json);

            try out.writer(self.allocator).print(
                "{{\"idx\":{d},\"name\":\"{s}\",\"mount_path\":\"{s}\",\"url\":\"{s}\",\"export\":\"{s}\",\"root\":{d},\"export_ro\":{s},\"source_kind\":{s},\"source_id\":{s},\"caps\":{{\"native_watch\":{s},\"case_sensitive\":{s}}},\"healthy\":{s},\"has_client\":{s},\"has_auth\":{s},\"consecutive_failures\":{d},\"last_health_check_ms\":{d},\"last_success_ms\":{d},\"last_failure_ms\":{d}}}",
                .{
                    endpoint_index,
                    escaped_name,
                    escaped_mount,
                    escaped_url,
                    escaped_export,
                    endpoint.root_node_id,
                    optionalBoolJson(endpoint.export_read_only),
                    source_kind_json,
                    source_id_json,
                    optionalBoolJson(endpoint.caps_native_watch),
                    optionalBoolJson(endpoint.caps_case_sensitive),
                    if (endpoint.healthy) "true" else "false",
                    if (endpoint.client != null) "true" else "false",
                    if (endpoint.auth_token != null) "true" else "false",
                    endpoint.consecutive_failures,
                    endpoint.last_health_check_ms,
                    endpoint.last_success_ms,
                    endpoint.last_failure_ms,
                },
            );
        }

        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    pub fn getattr(self: *Router, path: []const u8) ![]u8 {
        const normalized_path = normalizeRouterPath(path);
        self.drainPendingInvalidations();
        if (std.mem.eql(u8, normalized_path, "/")) {
            return self.allocator.dupe(u8, "{\"id\":1,\"k\":2,\"m\":16877,\"n\":2,\"u\":0,\"g\":0,\"sz\":0,\"at\":0,\"mt\":0,\"ct\":0,\"gen\":0}");
        }
        if (self.isVirtualDirectoryPath(normalized_path)) {
            const node_id = virtualDirNodeId(normalized_path);
            return std.fmt.allocPrint(
                self.allocator,
                "{{\"id\":{d},\"k\":2,\"m\":16877,\"n\":2,\"u\":0,\"g\":0,\"sz\":0,\"at\":0,\"mt\":0,\"ct\":0,\"gen\":0}}",
                .{node_id},
            );
        }

        const node = try self.resolvePath(normalized_path, false, .read_data);
        const now = std.time.milliTimestamp();
        if (self.attr_cache.getFresh(.{ .endpoint_index = node.endpoint_index, .node_id = node.node_id }, now)) |cached| {
            return self.allocator.dupe(u8, cached);
        }

        const response = try self.callEndpoint(node.endpoint_index, .GETATTR, node.node_id, null, null);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        const attr = try extractAttrFromWrapper(self.allocator, response.result_json);
        defer self.allocator.free(attr.attr_json);
        try self.attr_cache.put(.{ .endpoint_index = node.endpoint_index, .node_id = node.node_id }, attr.attr_json, 0, now);
        return self.allocator.dupe(u8, attr.attr_json);
    }

    pub fn readdir(self: *Router, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        const normalized_path = normalizeRouterPath(path);
        self.drainPendingInvalidations();
        if (self.isVirtualDirectoryPath(normalized_path)) {
            return self.buildVirtualDirectoryListing(normalized_path, cookie, max_entries);
        }
        const node = try self.resolvePath(normalized_path, false, .read_data);
        const cache_key = fs_cache.NodeKey{
            .endpoint_index = node.endpoint_index,
            .node_id = node.node_id,
        };
        const now = std.time.milliTimestamp();
        if (cookie == 0) {
            if (self.dir_listing_cache.getFresh(cache_key, now)) |cached_listing| {
                return self.allocator.dupe(u8, cached_listing);
            }
        }

        const args = try std.fmt.allocPrint(self.allocator, "{{\"cookie\":{d},\"max\":{d}}}", .{ cookie, max_entries });
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .READDIRP, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        const update = try self.updateCachesFromReaddir(node.endpoint_index, node.node_id, response.result_json);
        if (cookie == 0) {
            try self.dir_prime_cache.markComplete(cache_key, std.time.milliTimestamp());
            if (update.complete) {
                try self.dir_listing_cache.put(cache_key, response.result_json, std.time.milliTimestamp());
                try self.dir_complete_cache.markComplete(cache_key, std.time.milliTimestamp());
            } else {
                self.dir_listing_cache.invalidateDir(node.endpoint_index, node.node_id);
                self.dir_complete_cache.invalidateDir(node.endpoint_index, node.node_id);
                self.dir_prime_cache.invalidateDir(node.endpoint_index, node.node_id);
            }
        }
        return self.allocator.dupe(u8, response.result_json);
    }

    pub fn statfs(self: *Router, path: []const u8) ![]u8 {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, false, .statfs);
        const response = try self.callEndpoint(node.endpoint_index, .STATFS, node.node_id, null, "{}");
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        return self.allocator.dupe(u8, response.result_json);
    }

    pub fn symlink(self: *Router, target: []const u8, link_path: []const u8) !void {
        self.drainPendingInvalidations();
        const split = try splitParentChild(link_path);
        const parent = try self.resolvePath(split.parent_path, true, .symlink);

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, split.name);
        defer self.allocator.free(escaped_name);
        const escaped_target = try fs_protocol.jsonEscape(self.allocator, target);
        defer self.allocator.free(escaped_target);
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"name\":\"{s}\",\"target\":\"{s}\"}}",
            .{ escaped_name, escaped_target },
        );
        defer self.allocator.free(args);

        const response = try self.callEndpoint(parent.endpoint_index, .SYMLINK, parent.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_listing_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_complete_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_prime_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.negative_cache.invalidateDir(parent.endpoint_index, parent.node_id);
    }

    pub fn setxattr(self: *Router, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, true, .xattr);
        const escaped_name = try fs_protocol.jsonEscape(self.allocator, name);
        defer self.allocator.free(escaped_name);
        const encoded = try encodeBase64(self.allocator, value);
        defer self.allocator.free(encoded);
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"name\":\"{s}\",\"value_b64\":\"{s}\",\"flags\":{d}}}",
            .{ escaped_name, encoded, flags },
        );
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .SETXATTR, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.attr_cache.invalidateNode(.{ .endpoint_index = node.endpoint_index, .node_id = node.node_id });
    }

    pub fn getxattr(self: *Router, path: []const u8, name: []const u8) ![]u8 {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, false, .xattr);
        const escaped_name = try fs_protocol.jsonEscape(self.allocator, name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .GETXATTR, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        return parseGetxattrResult(self.allocator, response.result_json);
    }

    pub fn listxattr(self: *Router, path: []const u8) ![]u8 {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, false, .xattr);
        const response = try self.callEndpoint(node.endpoint_index, .LISTXATTR, node.node_id, null, "{}");
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        return parseListxattrResult(self.allocator, response.result_json);
    }

    pub fn removexattr(self: *Router, path: []const u8, name: []const u8) !void {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, true, .xattr);
        const escaped_name = try fs_protocol.jsonEscape(self.allocator, name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .REMOVEXATTR, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.attr_cache.invalidateNode(.{ .endpoint_index = node.endpoint_index, .node_id = node.node_id });
    }

    pub fn open(self: *Router, path: []const u8, flags: u32) !OpenFile {
        self.drainPendingInvalidations();
        const desired_op: fs_source_policy.Operation = if (flagsRequireWrite(flags)) .write_data else .read_data;
        const node = try self.resolvePath(path, flagsRequireWrite(flags), desired_op);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"flags\":{d}}}", .{flags});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .OPEN, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        return try parseOpenResult(response.result_json, node.endpoint_index, node.node_id);
    }

    pub fn read(self: *Router, open_file: OpenFile, off: u64, len: u32) ![]u8 {
        self.drainPendingInvalidations();
        if (len == 0) return self.allocator.dupe(u8, "");

        const aligned = (off % self.block_size) == 0 and len == self.block_size;
        if (aligned) {
            if (self.read_cache.get(.{
                .endpoint_index = open_file.endpoint_index,
                .handle_id = open_file.handle_id,
                .block_index = off / self.block_size,
            })) |cached| {
                return self.allocator.dupe(u8, cached);
            }
        }

        const args = try std.fmt.allocPrint(self.allocator, "{{\"off\":{d},\"len\":{d}}}", .{ off, len });
        defer self.allocator.free(args);

        const response = try self.callEndpoint(open_file.endpoint_index, .READ, null, open_file.handle_id, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        const read_result = try parseReadResult(self.allocator, response.result_json);
        defer self.allocator.free(read_result.data);

        if (aligned) {
            try self.read_cache.put(.{
                .endpoint_index = open_file.endpoint_index,
                .handle_id = open_file.handle_id,
                .block_index = off / self.block_size,
            }, read_result.data);
        }
        return self.allocator.dupe(u8, read_result.data);
    }

    pub fn close(self: *Router, open_file: OpenFile) !void {
        self.drainPendingInvalidations();
        const response = try self.callEndpoint(open_file.endpoint_index, .CLOSE, null, open_file.handle_id, "{}");
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.read_cache.invalidateHandle(open_file.endpoint_index, open_file.handle_id);
    }

    pub fn lock(self: *Router, open_file: OpenFile, mode: LockMode, wait: bool) !void {
        self.drainPendingInvalidations();
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"kind\":\"{s}\",\"wait\":{}}}",
            .{ @tagName(mode), wait },
        );
        defer self.allocator.free(args);

        const response = try self.callEndpoint(open_file.endpoint_index, .LOCK, null, open_file.handle_id, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
    }

    pub fn create(self: *Router, path: []const u8, mode: u32, flags: u32) !OpenFile {
        self.drainPendingInvalidations();
        const split = try splitParentChild(path);
        const parent = try self.resolvePath(split.parent_path, true, .create);

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, split.name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"name\":\"{s}\",\"mode\":{d},\"flags\":{d}}}",
            .{ escaped_name, mode, flags },
        );
        defer self.allocator.free(args);

        const response = try self.callEndpoint(parent.endpoint_index, .CREATE, parent.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_listing_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_complete_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_prime_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.negative_cache.invalidateDir(parent.endpoint_index, parent.node_id);

        const open_file = try parseCreateResult(response.result_json, parent.endpoint_index);
        return open_file;
    }

    pub fn write(self: *Router, open_file: OpenFile, off: u64, data: []const u8) !u32 {
        self.drainPendingInvalidations();
        const encoded = try encodeBase64(self.allocator, data);
        defer self.allocator.free(encoded);

        const args = try std.fmt.allocPrint(self.allocator, "{{\"off\":{d},\"data_b64\":\"{s}\"}}", .{ off, encoded });
        defer self.allocator.free(args);

        const response = try self.callEndpoint(open_file.endpoint_index, .WRITE, null, open_file.handle_id, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        const bytes_written = try parseWriteResult(response.result_json);
        self.read_cache.invalidateHandle(open_file.endpoint_index, open_file.handle_id);
        return bytes_written;
    }

    pub fn truncate(self: *Router, path: []const u8, size: u64) !void {
        self.drainPendingInvalidations();
        const node = try self.resolvePath(path, true, .write_data);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"sz\":{d}}}", .{size});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(node.endpoint_index, .TRUNCATE, node.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.attr_cache.invalidateNode(.{ .endpoint_index = node.endpoint_index, .node_id = node.node_id });
    }

    pub fn unlink(self: *Router, path: []const u8) !void {
        self.drainPendingInvalidations();
        const split = try splitParentChild(path);
        const parent = try self.resolvePath(split.parent_path, true, .remove);

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, split.name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(parent.endpoint_index, .UNLINK, parent.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_listing_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_complete_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_prime_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.negative_cache.invalidateDir(parent.endpoint_index, parent.node_id);
    }

    pub fn mkdir(self: *Router, path: []const u8) !void {
        self.drainPendingInvalidations();
        const split = try splitParentChild(path);
        const parent = try self.resolvePath(split.parent_path, true, .create);

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, split.name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(parent.endpoint_index, .MKDIR, parent.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_listing_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_complete_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_prime_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.negative_cache.invalidateDir(parent.endpoint_index, parent.node_id);
    }

    pub fn rmdir(self: *Router, path: []const u8) !void {
        self.drainPendingInvalidations();
        const split = try splitParentChild(path);
        const parent = try self.resolvePath(split.parent_path, true, .remove);

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, split.name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(parent.endpoint_index, .RMDIR, parent.node_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_listing_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_complete_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.dir_prime_cache.invalidateDir(parent.endpoint_index, parent.node_id);
        self.negative_cache.invalidateDir(parent.endpoint_index, parent.node_id);
    }

    pub fn rename(self: *Router, old_path: []const u8, new_path: []const u8) !void {
        self.drainPendingInvalidations();
        const old_split = try splitParentChild(old_path);
        const new_split = try splitParentChild(new_path);
        const old_parent = try self.resolvePath(old_split.parent_path, true, .rename);
        const new_parent = try self.resolvePath(new_split.parent_path, true, .rename);
        if (old_parent.endpoint_index != new_parent.endpoint_index) {
            const old_endpoint = self.endpoints.items[old_parent.endpoint_index];
            const new_endpoint = self.endpoints.items[new_parent.endpoint_index];
            switch (decideCrossEndpointMove(
                endpointView(old_endpoint),
                endpointView(new_endpoint),
            )) {
                .allowed => {},
                .read_only => return RouterError.ReadOnlyFilesystem,
                .unsupported => return RouterError.CrossEndpointRename,
            }
            try self.renameCrossEndpointViaCopy(old_path, new_path, new_split.parent_path, old_parent, new_parent);
            return;
        }
        const endpoint = self.endpoints.items[old_parent.endpoint_index];
        if (isCaseOnlyRenameGuard(
            endpoint.caps_case_sensitive,
            old_parent.node_id == new_parent.node_id,
            old_split.name,
            new_split.name,
        )) {
            // Guardrail: on case-insensitive sources, treat case-only renames as no-ops.
            return;
        }

        const escaped_old = try fs_protocol.jsonEscape(self.allocator, old_split.name);
        defer self.allocator.free(escaped_old);
        const escaped_new = try fs_protocol.jsonEscape(self.allocator, new_split.name);
        defer self.allocator.free(escaped_new);
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"old_parent\":{d},\"old_name\":\"{s}\",\"new_parent\":{d},\"new_name\":\"{s}\"}}",
            .{ old_parent.node_id, escaped_old, new_parent.node_id, escaped_new },
        );
        defer self.allocator.free(args);

        const response = try self.callEndpoint(old_parent.endpoint_index, .RENAME, null, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);
        self.dir_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_listing_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_listing_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_complete_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_complete_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_prime_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_prime_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.negative_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.negative_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
    }

    fn renameCrossEndpointViaCopy(
        self: *Router,
        old_path: []const u8,
        new_path: []const u8,
        new_parent_path: []const u8,
        old_parent: ResolvedNode,
        new_parent: ResolvedNode,
    ) !void {
        const attr_json = try self.getattr(old_path);
        defer self.allocator.free(attr_json);
        const summary = try parseAttrSummary(attr_json);
        if (summary.kind != .file) return RouterError.CrossEndpointRename;

        const dest_exists = self.getattr(new_path) catch |err| switch (err) {
            RouterError.FileNotFound => null,
            else => return err,
        };
        if (dest_exists) |existing_attr_json| {
            defer self.allocator.free(existing_attr_json);
            const existing = try parseAttrSummary(existing_attr_json);
            if (existing.kind == .dir) return RouterError.IsDirectory;
            return RouterError.AlreadyExists;
        }

        const source_open = try self.open(old_path, 0);
        defer self.close(source_open) catch {};

        var temp_path: ?[]u8 = null;
        defer if (temp_path) |path| {
            self.unlink(path) catch {};
            self.allocator.free(path);
        };
        var temp_open: ?OpenFile = null;
        defer if (temp_open) |open_file| self.close(open_file) catch {};

        var attempt: u32 = 0;
        while (attempt < 32) : (attempt += 1) {
            const temp_name = try std.fmt.allocPrint(
                self.allocator,
                ".spiderweb-xmv-{d}-{d}.tmp",
                .{ std.time.nanoTimestamp(), attempt },
            );
            defer self.allocator.free(temp_name);
            const candidate = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ new_parent_path, temp_name });
            errdefer self.allocator.free(candidate);

            const created = self.create(candidate, summary.mode, 2) catch |err| switch (err) {
                RouterError.AlreadyExists => continue,
                else => return err,
            };
            temp_path = candidate;
            temp_open = created;
            break;
        }
        if (temp_path == null or temp_open == null) return RouterError.AlreadyExists;

        var offset: u64 = 0;
        const chunk_len: u32 = if (self.block_size == 0) 256 * 1024 else self.block_size;
        while (true) {
            const chunk = try self.read(source_open, offset, chunk_len);
            defer self.allocator.free(chunk);
            if (chunk.len == 0) break;

            _ = try self.write(temp_open.?, offset, chunk);
            offset += chunk.len;
            if (chunk.len < chunk_len) break;
        }

        try self.close(temp_open.?);
        temp_open = null;

        const temp_name = std.fs.path.basename(temp_path.?);
        const new_split = try splitParentChild(new_path);
        const escaped_old = try fs_protocol.jsonEscape(self.allocator, temp_name);
        defer self.allocator.free(escaped_old);
        const escaped_new = try fs_protocol.jsonEscape(self.allocator, new_split.name);
        defer self.allocator.free(escaped_new);
        const args = try std.fmt.allocPrint(
            self.allocator,
            "{{\"old_parent\":{d},\"old_name\":\"{s}\",\"new_parent\":{d},\"new_name\":\"{s}\"}}",
            .{ new_parent.node_id, escaped_old, new_parent.node_id, escaped_new },
        );
        defer self.allocator.free(args);

        const rename_response = try self.callEndpoint(new_parent.endpoint_index, .RENAME, null, null, args);
        defer rename_response.deinit(self.allocator);
        if (!rename_response.ok) return mapErrno(rename_response.err_no);
        self.allocator.free(temp_path.?);
        temp_path = null;

        self.unlink(old_path) catch |unlink_err| {
            self.unlink(new_path) catch {};
            return unlink_err;
        };

        self.attr_cache.invalidateNode(.{
            .endpoint_index = old_parent.endpoint_index,
            .node_id = source_open.node_id,
        });
        self.dir_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_listing_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_listing_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_complete_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_complete_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.dir_prime_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.dir_prime_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
        self.negative_cache.invalidateDir(old_parent.endpoint_index, old_parent.node_id);
        self.negative_cache.invalidateDir(new_parent.endpoint_index, new_parent.node_id);
    }

    fn addEndpoint(self: *Router, cfg: EndpointConfig) !void {
        const endpoint_index = self.endpoints.items.len;
        const mount_seed = if (cfg.mount_path) |path| path else blk: {
            break :blk try std.fmt.allocPrint(self.allocator, "/{s}", .{cfg.name});
        };
        defer if (cfg.mount_path == null) self.allocator.free(mount_seed);
        const mount_path = try normalizeMountPath(self.allocator, mount_seed);
        errdefer self.allocator.free(mount_path);

        try self.endpoints.append(self.allocator, .{
            .name = try self.allocator.dupe(u8, cfg.name),
            .url = try self.allocator.dupe(u8, cfg.url),
            .export_name = if (cfg.export_name) |value| try self.allocator.dupe(u8, value) else null,
            .mount_path = mount_path,
            .auth_token = if (cfg.auth_token) |value| try self.allocator.dupe(u8, value) else null,
            .root_node_id = 0,
            .client = null,
            .healthy = false,
            .last_health_check_ms = 0,
            .last_failure_ms = 0,
            .consecutive_failures = 0,
        });
        errdefer {
            if (self.endpoints.pop()) |removed_value| {
                var removed = removed_value;
                removed.deinit(self.allocator);
            }
        }
        // Keep startup non-blocking: endpoint transport handshakes are established lazily
        // on first real access instead of during topology install.
        const endpoint = &self.endpoints.items[endpoint_index];
        if (self.seedRootFromMountPath(endpoint.mount_path, endpoint_index)) |seeded_root| {
            endpoint.root_node_id = seeded_root;
        }
    }

    fn clearEndpoints(self: *Router) void {
        for (self.endpoints.items, 0..) |_, endpoint_index| self.stopEventPump(endpoint_index);
        for (self.endpoints.items) |*endpoint| endpoint.deinit(self.allocator);
        self.endpoints.clearRetainingCapacity();
    }

    fn clearPendingInvalidations(self: *Router) void {
        self.pending_invalidations_mutex.lock();
        var pending = self.pending_invalidations;
        self.pending_invalidations = .{};
        self.pending_invalidations_mutex.unlock();
        pending.deinit(self.allocator);
    }

    fn resolvePath(
        self: *Router,
        path: []const u8,
        require_writable: bool,
        desired_op: fs_source_policy.Operation,
    ) !ResolvedNode {
        const normalized_path = normalizeRouterPath(path);
        if (normalized_path.len == 0 or normalized_path[0] != '/') return RouterError.InvalidPath;

        var matched_prefix_len: usize = 0;
        var saw_matching_endpoint = false;
        for (self.endpoints.items) |endpoint| {
            if (matchPathToMount(normalized_path, endpoint.mount_path)) |matched| {
                saw_matching_endpoint = true;
                if (matched.mount_path_len > matched_prefix_len) {
                    matched_prefix_len = matched.mount_path_len;
                }
            }
        }

        if (!saw_matching_endpoint) return RouterError.UnknownEndpoint;

        var path_candidates = std.ArrayListUnmanaged(PathCandidate){};
        defer path_candidates.deinit(self.allocator);
        for (self.endpoints.items, 0..) |endpoint, endpoint_index| {
            const matched = matchPathToMount(normalized_path, endpoint.mount_path) orelse continue;
            if (matched.mount_path_len != matched_prefix_len) continue;
            try path_candidates.append(self.allocator, .{
                .endpoint_index = endpoint_index,
                .relative_path = matched.relative_path,
            });
        }

        var saw_endpoint_failure = false;
        var saw_readonly_endpoint = false;
        var saw_writable_candidate = false;
        var saw_incompatible_endpoint = false;
        var saw_supported_endpoint = false;
        var candidates = std.ArrayListUnmanaged(PathCandidate){};
        defer candidates.deinit(self.allocator);

        for (path_candidates.items) |candidate| {
            const endpoint = self.endpoints.items[candidate.endpoint_index];
            if (!endpointMatchesWriteRequirement(endpoint.export_read_only, require_writable)) {
                saw_readonly_endpoint = true;
                continue;
            }
            saw_writable_candidate = true;
            try candidates.append(self.allocator, candidate);
        }

        if (candidates.items.len == 0) {
            if (require_writable and self.isVirtualDirectoryPath(path)) return RouterError.ReadOnlyFilesystem;
            if (require_writable and !saw_writable_candidate and saw_readonly_endpoint) {
                return RouterError.ReadOnlyFilesystem;
            }
            return RouterError.IOError;
        }

        const attempted = try self.allocator.alloc(bool, candidates.items.len);
        defer self.allocator.free(attempted);

        for (0..2) |pass| {
            for (candidates.items) |candidate| {
                const endpoint_index = candidate.endpoint_index;
                self.refreshEndpointHealth(endpoint_index, pass == 1) catch |err| {
                    if (isEndpointFailureError(err)) {
                        self.noteEndpointFailure(endpoint_index);
                        saw_endpoint_failure = true;
                        continue;
                    }
                    return err;
                };
            }

            @memset(attempted, false);
            var attempt_count: usize = 0;
            var saw_candidate_failure = false;
            while (attempt_count < candidates.items.len) : (attempt_count += 1) {
                const picked_rank = pickBestEndpointCandidate(self, candidates.items, attempted, desired_op, require_writable) orelse break;
                attempted[picked_rank] = true;
                const candidate = candidates.items[picked_rank];
                const endpoint_index = candidate.endpoint_index;
                const endpoint = self.endpoints.items[endpoint_index];
                if (!endpointSupportsOperationForRouting(endpoint, desired_op)) {
                    saw_incompatible_endpoint = true;
                    continue;
                }
                saw_supported_endpoint = true;
                const resolved = self.resolvePathOnEndpoint(endpoint_index, candidate.relative_path) catch |err| {
                    if (isEndpointFailureError(err)) {
                        self.noteEndpointFailure(endpoint_index);
                        saw_endpoint_failure = true;
                        saw_candidate_failure = true;
                        continue;
                    }
                    return err;
                };
                if (saw_candidate_failure) {
                    self.failover_events_total +%= 1;
                    std.log.info(
                        "fs router failover path={s} selected endpoint={s} total={d}",
                        .{ normalized_path, self.endpoints.items[endpoint_index].name, self.failover_events_total },
                    );
                }
                return resolved;
            }
        }

        if (require_writable and !saw_writable_candidate and saw_readonly_endpoint) {
            return RouterError.ReadOnlyFilesystem;
        }
        if (!saw_supported_endpoint and saw_incompatible_endpoint) return RouterError.OperationNotSupported;
        if (saw_endpoint_failure) return RouterError.EndpointUnavailable;
        if (saw_incompatible_endpoint) return RouterError.OperationNotSupported;
        return RouterError.IOError;
    }

    fn resolvePathOnEndpoint(self: *Router, endpoint_index: usize, relative_path: []const u8) !ResolvedNode {
        const endpoint = &self.endpoints.items[endpoint_index];
        if (endpoint.root_node_id == 0 and endpoint.client == null) {
            self.reconnectEndpoint(endpoint_index) catch |err| {
                if (isEndpointFailureError(err)) {
                    self.noteEndpointFailure(endpoint_index);
                }
                return err;
            };
        }

        var node_id = self.endpoints.items[endpoint_index].root_node_id;
        var parent_id: ?u64 = null;
        var final_name: ?[]const u8 = null;
        var parts_it = std.mem.tokenizeScalar(u8, relative_path, '/');

        while (parts_it.next()) |name| {
            if (name.len == 0) continue;
            parent_id = node_id;
            final_name = name;
            node_id = try self.lookupChild(endpoint_index, node_id, name);
        }

        return .{
            .endpoint_index = @intCast(endpoint_index),
            .node_id = node_id,
            .parent_id = parent_id,
            .name = final_name,
        };
    }

    fn pickBestEndpointCandidate(
        self: *const Router,
        candidates: []const PathCandidate,
        attempted: []const bool,
        desired_op: fs_source_policy.Operation,
        require_writable: bool,
    ) ?usize {
        const now = std.time.milliTimestamp();
        var best_rank: ?usize = null;
        var best_score: i64 = std.math.minInt(i64);
        for (candidates, 0..) |candidate, rank_idx| {
            if (attempted[rank_idx]) continue;
            const score = endpointRoutingScore(self.endpoints.items[candidate.endpoint_index], desired_op, require_writable, now);
            if (best_rank == null or score > best_score) {
                best_rank = rank_idx;
                best_score = score;
            }
        }
        return best_rank;
    }

    fn lookupChild(self: *Router, endpoint_index: usize, parent_id: u64, name: []const u8) !u64 {
        const endpoint_u16: u16 = @intCast(endpoint_index);
        const dir_key = fs_cache.NodeKey{
            .endpoint_index = endpoint_u16,
            .node_id = parent_id,
        };
        const normalized_name = try normalizeNameForCache(
            self.allocator,
            self.endpoints.items[endpoint_index].caps_case_sensitive,
            name,
        );
        defer self.allocator.free(normalized_name);
        const now = std.time.milliTimestamp();
        if (self.negative_cache.containsFresh(endpoint_u16, parent_id, normalized_name, now)) {
            return RouterError.FileNotFound;
        }

        if (self.dir_cache.getFresh(endpoint_u16, parent_id, normalized_name, now)) |cached| {
            return cached.node_id;
        }

        if (self.dir_complete_cache.isFresh(dir_key, now)) {
            try self.negative_cache.put(endpoint_u16, parent_id, normalized_name, now);
            return RouterError.FileNotFound;
        }

        const escaped_name = try fs_protocol.jsonEscape(self.allocator, name);
        defer self.allocator.free(escaped_name);
        const args = try std.fmt.allocPrint(self.allocator, "{{\"name\":\"{s}\"}}", .{escaped_name});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(endpoint_u16, .LOOKUP, parent_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) {
            if (response.err_no == fs_protocol.Errno.ENOENT) {
                try self.negative_cache.put(endpoint_u16, parent_id, normalized_name, std.time.milliTimestamp());
            }
            return mapErrno(response.err_no);
        }

        const attr = try extractAttrFromWrapper(self.allocator, response.result_json);
        defer self.allocator.free(attr.attr_json);

        const now_after_lookup = std.time.milliTimestamp();
        try self.attr_cache.put(.{ .endpoint_index = endpoint_u16, .node_id = attr.node_id }, attr.attr_json, 0, now_after_lookup);
        try self.dir_cache.put(endpoint_u16, parent_id, normalized_name, attr.node_id, attr.attr_json, now_after_lookup);
        if (!self.dir_complete_cache.isFresh(dir_key, now_after_lookup) and !self.dir_prime_cache.isFresh(dir_key, now_after_lookup)) {
            try self.dir_prime_cache.markComplete(dir_key, now_after_lookup);
            self.primeDirectoryCache(endpoint_u16, parent_id) catch {};
        }
        return attr.node_id;
    }

    fn primeDirectoryCache(self: *Router, endpoint_index: u16, dir_id: u64) !void {
        const args = try std.fmt.allocPrint(self.allocator, "{{\"cookie\":0,\"max\":4096}}", .{});
        defer self.allocator.free(args);

        const response = try self.callEndpoint(endpoint_index, .READDIRP, dir_id, null, args);
        defer response.deinit(self.allocator);
        if (!response.ok) return mapErrno(response.err_no);

        const update = try self.updateCachesFromReaddir(endpoint_index, dir_id, response.result_json);
        if (update.complete) {
            try self.dir_complete_cache.markComplete(.{
                .endpoint_index = endpoint_index,
                .node_id = dir_id,
            }, std.time.milliTimestamp());
        }
    }

    fn callEndpoint(
        self: *Router,
        endpoint_index: u16,
        op: fs_protocol.Op,
        node: ?u64,
        handle: ?u64,
        args_json: ?[]const u8,
    ) !fs_client.ClientResponse {
        self.armEventPumps();
        self.drainPendingInvalidations();
        const endpoint_usize: usize = endpoint_index;
        const endpoint = &self.endpoints.items[endpoint_usize];
        var event_ctx = EventDispatchContext{
            .router = self,
            .endpoint_index = endpoint_index,
        };

        if (endpoint.client == null) {
            self.reconnectEndpoint(endpoint_usize) catch |err| {
                if (isEndpointFailureError(err)) {
                    self.noteEndpointFailure(endpoint_usize);
                }
                return err;
            };
        }

        var response = endpoint.client.?.call(
            op,
            node,
            handle,
            args_json,
            handleClientEvent,
            @ptrCast(&event_ctx),
        ) catch |err| {
            if (!isEndpointFailureError(err)) return err;

            self.noteEndpointFailure(endpoint_usize);
            self.reconnectEndpoint(endpoint_usize) catch |reconnect_err| {
                if (isEndpointFailureError(reconnect_err)) {
                    self.noteEndpointFailure(endpoint_usize);
                    return err;
                }
                return reconnect_err;
            };

            const retried = self.endpoints.items[endpoint_usize].client.?.call(
                op,
                node,
                handle,
                args_json,
                handleClientEvent,
                @ptrCast(&event_ctx),
            ) catch |retry_err| {
                if (isEndpointFailureError(retry_err)) {
                    self.noteEndpointFailure(endpoint_usize);
                }
                return retry_err;
            };
            self.drainPendingInvalidations();
            self.noteEndpointSuccess(endpoint_usize);
            return retried;
        };

        if (!response.ok and shouldRetryEndpointErrnoAfterReconnect(op, response.err_no)) {
            self.noteEndpointFailure(endpoint_usize);
            self.reconnectEndpoint(endpoint_usize) catch |reconnect_err| {
                if (isEndpointFailureError(reconnect_err)) {
                    self.noteEndpointFailure(endpoint_usize);
                }
                self.drainPendingInvalidations();
                return response;
            };

            response.deinit(self.allocator);
            response = self.endpoints.items[endpoint_usize].client.?.call(
                op,
                node,
                handle,
                args_json,
                handleClientEvent,
                @ptrCast(&event_ctx),
            ) catch |retry_err| {
                if (isEndpointFailureError(retry_err)) {
                    self.noteEndpointFailure(endpoint_usize);
                }
                return retry_err;
            };
        }

        self.drainPendingInvalidations();
        self.noteEndpointSuccess(endpoint_usize);
        return response;
    }

    fn reconnectEndpoint(self: *Router, endpoint_index: usize) !void {
        const endpoint = &self.endpoints.items[endpoint_index];
        var replacement = try fs_client.FsClient.connect(self.allocator, endpoint.url);
        errdefer replacement.deinit();

        const hello_payload = try self.buildFsHelloPayload(endpoint, false);
        defer self.allocator.free(hello_payload);

        var hello = try replacement.call(.HELLO, null, null, hello_payload, null, null);
        hello.deinit(self.allocator);

        var exports = try replacement.call(.EXPORTS, null, null, "{}", null, null);
        defer exports.deinit(self.allocator);
        if (!exports.ok) return mapErrno(exports.err_no);

        var selected = try pickExportInfo(self.allocator, exports.result_json, endpoint.export_name);
        errdefer selected.deinit(self.allocator);
        if (endpoint.client) |*existing| {
            existing.deinit();
        }
        endpoint.clearExportMetadata(self.allocator);
        endpoint.client = replacement;
        endpoint.root_node_id = selected.root_id;
        endpoint.export_read_only = selected.read_only;
        endpoint.source_kind = selected.source_kind;
        endpoint.source_id = selected.source_id;
        endpoint.caps_native_watch = selected.native_watch;
        endpoint.caps_case_sensitive = selected.case_sensitive;
        selected.source_kind = null;
        selected.source_id = null;
        self.noteEndpointSuccess(endpoint_index);
        if (self.event_pumps_armed) {
            self.restartEventPump(endpoint_index) catch |err| {
                std.log.warn("fs router event pump unavailable for endpoint {d}: {s}", .{ endpoint_index, @errorName(err) });
            };
        }
    }

    const EventDispatchContext = struct {
        router: *Router,
        endpoint_index: u16,
    };

    fn handleClientEvent(ctx: ?*anyopaque, event: fs_protocol.InvalidationEvent) void {
        const raw = ctx orelse return;
        const event_ctx: *EventDispatchContext = @ptrCast(@alignCast(raw));
        event_ctx.router.queueInvalidation(event_ctx.endpoint_index, event);
    }

    fn queueInvalidation(self: *Router, endpoint_index: u16, event: fs_protocol.InvalidationEvent) void {
        self.pending_invalidations_mutex.lock();
        defer self.pending_invalidations_mutex.unlock();
        self.pending_invalidations.append(self.allocator, .{
            .endpoint_index = endpoint_index,
            .event = event,
        }) catch {};
    }

    fn drainPendingInvalidations(self: *Router) void {
        var pending = std.ArrayListUnmanaged(PendingInvalidation){};

        self.pending_invalidations_mutex.lock();
        pending = self.pending_invalidations;
        self.pending_invalidations = .{};
        self.pending_invalidations_mutex.unlock();
        defer pending.deinit(self.allocator);

        for (pending.items) |item| {
            self.applyInvalidationEvent(item.endpoint_index, item.event);
        }
    }

    fn armEventPumps(self: *Router) void {
        if (self.event_pumps_armed) return;
        self.event_pumps_armed = true;
        for (self.endpoints.items, 0..) |endpoint, endpoint_index| {
            if (endpoint.client == null) continue;
            self.restartEventPump(endpoint_index) catch |err| {
                std.log.warn(
                    "fs router event pump unavailable for endpoint {d}: {s}",
                    .{ endpoint_index, @errorName(err) },
                );
            };
        }
    }

    fn restartEventPump(self: *Router, endpoint_index: usize) !void {
        self.stopEventPump(endpoint_index);
        const endpoint = &self.endpoints.items[endpoint_index];

        var event_client = try fs_client.FsClient.connect(self.allocator, endpoint.url);
        errdefer event_client.deinit();

        const hello_payload = try self.buildFsHelloPayload(endpoint, true);
        defer self.allocator.free(hello_payload);
        var hello = try event_client.call(.HELLO, null, null, hello_payload, null, null);
        hello.deinit(self.allocator);

        endpoint.event_client = event_client;
        errdefer {
            if (endpoint.event_client) |*client| {
                client.deinit();
                endpoint.event_client = null;
            }
        }
        endpoint.event_mutex.lock();
        endpoint.event_stop = false;
        endpoint.event_mutex.unlock();
        endpoint.event_thread = try std.Thread.spawn(
            .{},
            eventPumpThreadMain,
            .{ self, @as(u16, @intCast(endpoint_index)) },
        );
    }

    fn stopEventPump(self: *Router, endpoint_index: usize) void {
        const endpoint = &self.endpoints.items[endpoint_index];

        endpoint.event_mutex.lock();
        endpoint.event_stop = true;
        endpoint.event_mutex.unlock();

        if (endpoint.event_thread) |thread| {
            thread.join();
            endpoint.event_thread = null;
        }
        if (endpoint.event_client) |*client| {
            client.deinit();
            endpoint.event_client = null;
        }
    }

    fn shouldStopEventPump(endpoint: *Endpoint) bool {
        endpoint.event_mutex.lock();
        defer endpoint.event_mutex.unlock();
        return endpoint.event_stop;
    }

    fn eventPumpThreadMain(self: *Router, endpoint_index: u16) void {
        const endpoint_usize: usize = endpoint_index;
        while (true) {
            if (endpoint_usize >= self.endpoints.items.len) return;
            const endpoint = &self.endpoints.items[endpoint_usize];
            if (shouldStopEventPump(endpoint)) return;
            if (endpoint.event_client == null) return;

            var event_ctx = EventDispatchContext{
                .router = self,
                .endpoint_index = endpoint_index,
            };

            endpoint.event_client.?.pumpEvents(
                250,
                handleClientEvent,
                @ptrCast(&event_ctx),
            ) catch |err| {
                if (isEndpointFailureError(err)) return;
                std.log.warn(
                    "fs router event pump error endpoint {d}: {s}",
                    .{ endpoint_index, @errorName(err) },
                );
                std.Thread.sleep(250 * std.time.ns_per_ms);
            };
        }
    }

    fn applyInvalidationEvent(self: *Router, endpoint_index: u16, event: fs_protocol.InvalidationEvent) void {
        switch (event) {
            .INVAL => |ev| {
                self.attr_cache.invalidateNode(.{
                    .endpoint_index = endpoint_index,
                    .node_id = ev.node,
                });

                if (ev.what == .all) {
                    self.dir_cache.invalidateDir(endpoint_index, ev.node);
                    self.dir_listing_cache.invalidateDir(endpoint_index, ev.node);
                    self.dir_complete_cache.invalidateDir(endpoint_index, ev.node);
                    self.dir_prime_cache.invalidateDir(endpoint_index, ev.node);
                    self.negative_cache.invalidateDir(endpoint_index, ev.node);
                }

                if (ev.what != .attr) {
                    self.read_cache.invalidateEndpoint(endpoint_index);
                }
            },
            .INVAL_DIR => |ev| {
                self.attr_cache.invalidateNode(.{
                    .endpoint_index = endpoint_index,
                    .node_id = ev.dir,
                });
                self.dir_cache.invalidateDir(endpoint_index, ev.dir);
                self.dir_listing_cache.invalidateDir(endpoint_index, ev.dir);
                self.dir_complete_cache.invalidateDir(endpoint_index, ev.dir);
                self.dir_prime_cache.invalidateDir(endpoint_index, ev.dir);
                self.negative_cache.invalidateDir(endpoint_index, ev.dir);
            },
        }
    }

    fn refreshEndpointHealth(self: *Router, endpoint_index: usize, force: bool) !void {
        const now = std.time.milliTimestamp();
        const endpoint = &self.endpoints.items[endpoint_index];

        if (!force) {
            if (endpoint.last_health_check_ms != 0 and now - endpoint.last_health_check_ms < self.health_check_interval_ms) return;
            if (!endpoint.healthy and endpoint.last_failure_ms != 0 and now - endpoint.last_failure_ms < self.unhealthy_retry_interval_ms) return;
        }

        endpoint.last_health_check_ms = now;
        const hello_payload = try self.buildFsHelloPayload(endpoint, false);
        defer self.allocator.free(hello_payload);
        var hello = self.callEndpoint(@intCast(endpoint_index), .HELLO, null, null, hello_payload) catch |err| {
            if (isEndpointFailureError(err)) {
                self.noteEndpointFailure(endpoint_index);
                return;
            }
            return err;
        };
        hello.deinit(self.allocator);
    }

    fn buildFsHelloPayload(self: *Router, endpoint: *const Endpoint, subscribe_invalidations: bool) ![]u8 {
        if (endpoint.auth_token) |auth_token| {
            const escaped_auth = try fs_protocol.jsonEscape(self.allocator, auth_token);
            defer self.allocator.free(escaped_auth);
            return std.fmt.allocPrint(
                self.allocator,
                "{{\"protocol\":\"{s}\",\"proto\":{d},\"auth_token\":\"{s}\",\"subscribe_invalidations\":{s}}}",
                .{
                    fsrpc_node_protocol_version,
                    fsrpc_node_proto_id,
                    escaped_auth,
                    if (subscribe_invalidations) "true" else "false",
                },
            );
        }

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"protocol\":\"{s}\",\"proto\":{d},\"subscribe_invalidations\":{s}}}",
            .{
                fsrpc_node_protocol_version,
                fsrpc_node_proto_id,
                if (subscribe_invalidations) "true" else "false",
            },
        );
    }

    fn noteEndpointSuccess(self: *Router, endpoint_index: usize) void {
        const endpoint = &self.endpoints.items[endpoint_index];
        const now = std.time.milliTimestamp();
        endpoint.healthy = true;
        endpoint.consecutive_failures = 0;
        endpoint.last_health_check_ms = now;
        endpoint.last_success_ms = now;
    }

    fn noteEndpointFailure(self: *Router, endpoint_index: usize) void {
        const endpoint = &self.endpoints.items[endpoint_index];
        endpoint.healthy = false;
        endpoint.consecutive_failures +|= 1;
        endpoint.last_failure_ms = std.time.milliTimestamp();
        endpoint.last_health_check_ms = endpoint.last_failure_ms;
    }

    fn seedRootFromMountPath(self: *const Router, mount_path: []const u8, exclude_index: usize) ?u64 {
        for (self.endpoints.items, 0..) |endpoint, endpoint_index| {
            if (endpoint_index == exclude_index) continue;
            if (!std.mem.eql(u8, endpoint.mount_path, mount_path)) continue;
            if (endpoint.root_node_id != 0) return endpoint.root_node_id;
        }
        return null;
    }

    const ReaddirCacheUpdate = struct {
        complete: bool,
        next_cookie: u64,
    };

    fn updateCachesFromReaddir(self: *Router, endpoint_index: u16, dir_id: u64, payload_json: []const u8) !ReaddirCacheUpdate {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return .{ .complete = false, .next_cookie = 0 };
        const next_cookie = parsed.value.object.get("next_cookie");
        const parsed_next_cookie: u64 = if (next_cookie) |value|
            (if (value == .integer and value.integer >= 0) @as(u64, @intCast(value.integer)) else 0)
        else
            0;
        const complete = parsed_next_cookie == 0;
        const ents = parsed.value.object.get("ents") orelse return .{ .complete = complete, .next_cookie = parsed_next_cookie };
        if (ents != .array) return .{ .complete = complete, .next_cookie = parsed_next_cookie };

        const now = std.time.milliTimestamp();
        for (ents.array.items) |entry| {
            if (entry != .object) continue;
            const name_val = entry.object.get("name") orelse continue;
            const attr_val = entry.object.get("attr") orelse continue;
            if (name_val != .string or attr_val != .object) continue;

            const node_id = extractNodeIdFromAttrValue(attr_val) catch continue;
            const attr_json = try std.fmt.allocPrint(self.allocator, "{f}", .{std.json.fmt(attr_val, .{})});
            defer self.allocator.free(attr_json);
            try self.attr_cache.put(.{ .endpoint_index = endpoint_index, .node_id = node_id }, attr_json, 0, now);
            const normalized_name = try normalizeNameForCache(
                self.allocator,
                self.endpoints.items[endpoint_index].caps_case_sensitive,
                name_val.string,
            );
            defer self.allocator.free(normalized_name);
            try self.dir_cache.put(endpoint_index, dir_id, normalized_name, node_id, attr_json, now);
        }
        return .{ .complete = complete, .next_cookie = parsed_next_cookie };
    }

    fn isVirtualDirectoryPath(self: *const Router, path: []const u8) bool {
        const normalized_path = normalizeRouterPath(path);
        if (normalized_path.len == 0 or normalized_path[0] != '/') return false;

        for (self.endpoints.items) |endpoint| {
            if (std.mem.eql(u8, normalized_path, endpoint.mount_path)) return false;
        }
        if (std.mem.eql(u8, normalized_path, "/")) return true;
        for (self.endpoints.items) |endpoint| {
            if (isStrictAncestorPath(normalized_path, endpoint.mount_path)) return true;
        }
        return false;
    }

    fn buildVirtualDirectoryListing(self: *Router, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        const normalized_path = normalizeRouterPath(path);
        var children = std.ArrayListUnmanaged([]const u8){};
        defer children.deinit(self.allocator);

        for (self.endpoints.items) |endpoint| {
            const child = childSegmentForVirtualDir(normalized_path, endpoint.mount_path) orelse continue;
            var exists = false;
            for (children.items) |seen| {
                if (std.mem.eql(u8, seen, child)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                try children.append(self.allocator, child);
            }
        }

        const start: usize = if (cookie > children.items.len) children.items.len else @intCast(cookie);
        const max_count: usize = if (max_entries == 0) 0 else @intCast(max_entries);
        const end = @min(children.items.len, start + max_count);
        const next_cookie: u64 = if (end < children.items.len) @intCast(end) else 0;

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"ents\":[");
        for (children.items[start..end], start..) |name, idx| {
            if (idx != start) try out.append(self.allocator, ',');

            const escaped_name = try fs_protocol.jsonEscape(self.allocator, name);
            defer self.allocator.free(escaped_name);
            const child_path = try joinPath(normalized_path, name, self.allocator);
            defer self.allocator.free(child_path);
            const node_id = virtualDirNodeId(child_path);

            try out.writer(self.allocator).print(
                "{{\"name\":\"{s}\",\"attr\":{{\"id\":{d},\"k\":2,\"m\":16877,\"n\":2,\"u\":0,\"g\":0,\"sz\":0,\"at\":0,\"mt\":0,\"ct\":0,\"gen\":0}}}}",
                .{ escaped_name, node_id },
            );
        }
        try out.writer(self.allocator).print("],\"next_cookie\":{d}}}", .{next_cookie});
        return out.toOwnedSlice(self.allocator);
    }
};

const MountMatch = struct {
    mount_path_len: usize,
    relative_path: []const u8,
};

fn matchPathToMount(path: []const u8, mount_path: []const u8) ?MountMatch {
    const normalized_path = normalizeRouterPath(path);
    const normalized_mount = normalizeRouterPath(mount_path);
    if (normalized_path.len == 0 or normalized_path[0] != '/') return null;
    if (normalized_mount.len == 0 or normalized_mount[0] != '/') return null;

    if (std.mem.eql(u8, normalized_mount, "/")) {
        if (std.mem.eql(u8, normalized_path, "/")) return .{ .mount_path_len = 1, .relative_path = "" };
        var relative = normalized_path[1..];
        while (relative.len > 0 and relative[0] == '/') relative = relative[1..];
        return .{ .mount_path_len = 1, .relative_path = relative };
    }

    if (!std.mem.startsWith(u8, normalized_path, normalized_mount)) return null;
    if (normalized_path.len == normalized_mount.len) {
        return .{
            .mount_path_len = normalized_mount.len,
            .relative_path = "",
        };
    }
    if (normalized_path[normalized_mount.len] != '/') return null;

    var relative = normalized_path[normalized_mount.len + 1 ..];
    while (relative.len > 0 and relative[0] == '/') relative = relative[1..];
    return .{
        .mount_path_len = normalized_mount.len,
        .relative_path = relative,
    };
}

fn isStrictAncestorPath(ancestor: []const u8, descendant: []const u8) bool {
    const normalized_ancestor = normalizeRouterPath(ancestor);
    const normalized_descendant = normalizeRouterPath(descendant);
    if (normalized_ancestor.len == 0 or normalized_descendant.len == 0) return false;
    if (!std.mem.startsWith(u8, normalized_descendant, normalized_ancestor)) return false;
    if (normalized_ancestor.len >= normalized_descendant.len) return false;
    if (std.mem.eql(u8, normalized_ancestor, "/")) return true;
    return normalized_descendant[normalized_ancestor.len] == '/';
}

fn childSegmentForVirtualDir(path: []const u8, mount_path: []const u8) ?[]const u8 {
    const normalized_path = normalizeRouterPath(path);
    const normalized_mount = normalizeRouterPath(mount_path);
    if (std.mem.eql(u8, normalized_path, normalized_mount)) return null;
    if (!isStrictAncestorPath(normalized_path, normalized_mount)) return null;

    const remainder = if (std.mem.eql(u8, normalized_path, "/"))
        normalized_mount[1..]
    else
        normalized_mount[normalized_path.len + 1 ..];
    if (remainder.len == 0) return null;
    const slash = std.mem.indexOfScalar(u8, remainder, '/') orelse remainder.len;
    if (slash == 0) return null;
    return remainder[0..slash];
}

fn normalizeRouterPath(path: []const u8) []const u8 {
    if (path.len <= 1) return path;
    var end = path.len;
    while (end > 1 and path[end - 1] == '/') : (end -= 1) {}
    return path[0..end];
}

fn virtualDirNodeId(path: []const u8) u64 {
    // Keep synthetic inode ids positive and <= maxInt(i64) so downstream JSON parsing
    // in FUSE adapters (which use signed integer JSON values) never overflows.
    const hashed = std.hash.Wyhash.hash(0x5350_5756_4449_5231, path);
    const normalized = (hashed & 0x3fff_ffff_ffff_ffff) | 0x4000_0000_0000_0000;
    return if (normalized == 1) 2 else normalized;
}

fn optionalSliceEql(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null and right == null) return true;
    if (left == null or right == null) return false;
    return std.mem.eql(u8, left.?, right.?);
}

fn normalizeMountPath(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return RouterError.InvalidPath;

    trimmed = std.mem.trim(u8, trimmed, "/");
    if (trimmed.len == 0) return allocator.dupe(u8, "/");
    return std.fmt.allocPrint(allocator, "/{s}", .{trimmed});
}

fn joinPath(base: []const u8, child: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (std.mem.eql(u8, base, "/")) return std.fmt.allocPrint(allocator, "/{s}", .{child});
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, child });
}

fn isEndpointFailureError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.EndOfStream,
        error.HandshakeRejected,
        error.ResponseTooLarge,
        error.InvalidFrameOpcode,
        error.UnsupportedFragmentation,
        error.UnexpectedMaskedFrame,
        error.FrameTooLarge,
        error.RequestIdMismatch,
        error.InvalidResponse,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.ConnectionTimedOut,
        error.TimedOut,
        error.NetworkUnreachable,
        error.HostUnreachable,
        => true,
        else => false,
    };
}

fn shouldRetryEndpointErrnoAfterReconnect(op: fs_protocol.Op, err_no: i32) bool {
    if (!isIdempotentEndpointOp(op)) return false;
    return switch (err_no) {
        fs_protocol.Errno.EIO,
        fs_protocol.Errno.ETIMEDOUT,
        fs_protocol.Errno.EAGAIN,
        fs_protocol.Errno.EBADF,
        => true,
        else => false,
    };
}

fn isIdempotentEndpointOp(op: fs_protocol.Op) bool {
    return switch (op) {
        .LOOKUP,
        .GETATTR,
        .READDIRP,
        .OPEN,
        .READ,
        .GETXATTR,
        .LISTXATTR,
        .STATFS,
        => true,
        else => false,
    };
}

fn mapErrno(errno_no: i32) RouterError {
    return switch (errno_no) {
        fs_protocol.Errno.ENOENT => RouterError.FileNotFound,
        fs_protocol.Errno.ENODATA => RouterError.NoData,
        fs_protocol.Errno.EAGAIN => RouterError.WouldBlock,
        fs_protocol.Errno.ERANGE => RouterError.Range,
        fs_protocol.Errno.EACCES => RouterError.PermissionDenied,
        fs_protocol.Errno.ENOTDIR => RouterError.NotDirectory,
        fs_protocol.Errno.EISDIR => RouterError.IsDirectory,
        fs_protocol.Errno.EEXIST => RouterError.AlreadyExists,
        fs_protocol.Errno.ENOSPC => RouterError.NoSpace,
        fs_protocol.Errno.ENOSYS => RouterError.OperationNotSupported,
        fs_protocol.Errno.EXDEV => RouterError.CrossEndpointRename,
        fs_protocol.Errno.EROFS => RouterError.ReadOnlyFilesystem,
        else => RouterError.IOError,
    };
}

fn endpointMatchesWriteRequirement(export_read_only: ?bool, require_writable: bool) bool {
    return fs_source_policy.allowsWritePathResolution(
        .{
            .read_only = export_read_only,
        },
        require_writable,
    );
}

fn optionalBoolJson(value: ?bool) []const u8 {
    if (value == null) return "null";
    return if (value.?) "true" else "false";
}

fn endpointView(endpoint: Endpoint) fs_source_policy.EndpointView {
    return .{
        .read_only = endpoint.export_read_only,
        .source_kind = endpoint.source_kind,
        .case_sensitive = endpoint.caps_case_sensitive,
    };
}

fn endpointSupportsOperationForRouting(endpoint: Endpoint, desired_op: fs_source_policy.Operation) bool {
    // Fresh endpoints may not have export metadata yet; allow one optimistic route
    // attempt so reconnect/export hydration can establish true capabilities.
    if (endpoint.source_kind == null) return true;
    return fs_source_policy.supports(endpointView(endpoint), desired_op);
}

fn endpointRoutingScore(
    endpoint: Endpoint,
    desired_op: fs_source_policy.Operation,
    require_writable: bool,
    now_ms: i64,
) i64 {
    var score: i64 = 0;
    if (endpoint.healthy) {
        score += 1000;
    } else {
        score -= 2000;
    }

    if (!endpointSupportsOperationForRouting(endpoint, desired_op)) score -= 10_000;
    if (require_writable and endpoint.export_read_only == true) score -= 10_000;

    if (endpoint.caps_native_watch == true) score += 20;
    score -= @as(i64, endpoint.consecutive_failures) * 200;

    if (endpoint.last_success_ms > 0) {
        const success_age = now_ms - endpoint.last_success_ms;
        if (success_age >= 0 and success_age < 30_000) {
            score += @divFloor(30_000 - success_age, 100);
        }
    }

    if (endpoint.last_failure_ms > 0) {
        const fail_age = now_ms - endpoint.last_failure_ms;
        if (fail_age >= 0 and fail_age < 30_000) {
            score -= @divFloor(30_000 - fail_age, 50);
        }
    }

    return score;
}

const CrossEndpointMoveDecision = enum {
    allowed,
    read_only,
    unsupported,
};

fn decideCrossEndpointMove(src: fs_source_policy.EndpointView, dst: fs_source_policy.EndpointView) CrossEndpointMoveDecision {
    if (src.read_only == true or dst.read_only == true) return .read_only;
    if (!fs_source_policy.allowsCrossEndpointCopyFallback(src, dst)) return .unsupported;
    return .allowed;
}

fn flagsRequireWrite(flags: u32) bool {
    const access_mode = flags & 0x3;
    return access_mode == 1 or access_mode == 2;
}

fn pickExportInfo(allocator: std.mem.Allocator, json: []const u8, desired_name: ?[]const u8) !SelectedExport {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const exports = parsed.value.object.get("exports") orelse return RouterError.InvalidResponse;
    if (exports != .array or exports.array.items.len == 0) return RouterError.InvalidResponse;

    var selected_item: ?std.json.Value = null;
    if (desired_name) |target| {
        for (exports.array.items) |item| {
            if (item != .object) continue;
            const name = item.object.get("name") orelse continue;
            if (name != .string) continue;
            if (std.mem.eql(u8, name.string, target)) {
                selected_item = item;
                break;
            }
        }
    } else {
        selected_item = exports.array.items[0];
    }

    const picked = selected_item orelse return RouterError.InvalidResponse;
    if (picked != .object) return RouterError.InvalidResponse;
    const root = picked.object.get("root") orelse return RouterError.InvalidResponse;
    if (root != .integer or root.integer < 0) return RouterError.InvalidResponse;

    var out = SelectedExport{
        .root_id = @intCast(root.integer),
        .read_only = jsonOptionalBool(picked.object.get("ro")),
        .source_kind = try jsonOptionalStringDup(allocator, picked.object.get("source_kind")),
        .source_id = try jsonOptionalStringDup(allocator, picked.object.get("source_id")),
    };
    errdefer out.deinit(allocator);

    if (picked.object.get("caps")) |caps_val| {
        if (caps_val == .object) {
            out.native_watch = jsonOptionalBool(caps_val.object.get("native_watch"));
            out.case_sensitive = jsonOptionalBool(caps_val.object.get("case_sensitive"));
        }
    }

    return out;
}

fn jsonOptionalBool(value: ?std.json.Value) ?bool {
    const resolved = value orelse return null;
    if (resolved != .bool) return null;
    return resolved.bool;
}

fn jsonOptionalStringDup(allocator: std.mem.Allocator, value: ?std.json.Value) !?[]u8 {
    const resolved = value orelse return null;
    if (resolved != .string) return null;
    const duplicated = try allocator.dupe(u8, resolved.string);
    return duplicated;
}

fn splitParentChild(path: []const u8) !struct { parent_path: []const u8, name: []const u8 } {
    if (path.len == 0 or path[0] != '/') return RouterError.InvalidPath;
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return RouterError.InvalidPath;
    if (slash == path.len - 1) return RouterError.InvalidPath;

    if (slash == 0) {
        const name_root = path[1..];
        if (name_root.len == 0) return RouterError.InvalidPath;
        return .{ .parent_path = "/", .name = name_root };
    }

    const parent = path[0..slash];
    const name = path[slash + 1 ..];
    if (parent.len == 0) return RouterError.InvalidPath;
    return .{ .parent_path = parent, .name = name };
}

fn normalizeNameForCache(allocator: std.mem.Allocator, case_sensitive: ?bool, name: []const u8) ![]u8 {
    return fs_source_policy.normalizeNameForCache(
        allocator,
        .{
            .case_sensitive = case_sensitive,
        },
        name,
    );
}

fn isCaseOnlyRenameGuard(case_sensitive: ?bool, same_parent: bool, old_name: []const u8, new_name: []const u8) bool {
    return fs_source_policy.isCaseOnlyRenameNoop(
        .{
            .case_sensitive = case_sensitive,
        },
        same_parent,
        old_name,
        new_name,
    );
}

const AttrExtract = struct {
    node_id: u64,
    attr_json: []u8,
};

const AttrKind = enum {
    file,
    dir,
    other,
};

const AttrSummary = struct {
    mode: u32,
    kind: AttrKind,
};

fn parseAttrSummary(attr_json: []const u8) !AttrSummary {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, attr_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;

    const mode_val = parsed.value.object.get("m") orelse return RouterError.InvalidResponse;
    if (mode_val != .integer or mode_val.integer < 0) return RouterError.InvalidResponse;
    const mode: u32 = @intCast(mode_val.integer);
    const kind = if (parsed.value.object.get("k")) |kind_val|
        switch (kind_val) {
            .integer => switch (kind_val.integer) {
                1 => AttrKind.file,
                2 => AttrKind.dir,
                else => AttrKind.other,
            },
            else => kindFromMode(mode),
        }
    else
        kindFromMode(mode);

    return .{
        .mode = mode,
        .kind = kind,
    };
}

fn kindFromMode(mode: u32) AttrKind {
    const file_type = mode & 0o170000;
    return switch (file_type) {
        0o040000 => .dir,
        0o100000 => .file,
        else => .other,
    };
}

fn extractAttrFromWrapper(allocator: std.mem.Allocator, json: []const u8) !AttrExtract {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const attr_val = parsed.value.object.get("attr") orelse return RouterError.InvalidResponse;
    if (attr_val != .object) return RouterError.InvalidResponse;

    const attr_json = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(attr_val, .{})});
    const node_id = try extractNodeIdFromAttr(attr_json);
    return .{
        .node_id = node_id,
        .attr_json = attr_json,
    };
}

fn extractNodeIdFromAttr(attr_json: []const u8) !u64 {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, attr_json, .{});
    defer parsed.deinit();
    return extractNodeIdFromAttrValue(parsed.value);
}

fn extractNodeIdFromAttrValue(attr_value: std.json.Value) !u64 {
    if (attr_value != .object) return RouterError.InvalidResponse;
    const id_val = attr_value.object.get("id") orelse return RouterError.InvalidResponse;
    if (id_val != .integer or id_val.integer < 0) return RouterError.InvalidResponse;
    return @intCast(id_val.integer);
}

fn parseOpenResult(json: []const u8, endpoint_index: u16, node_id: u64) !OpenFile {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const h = parsed.value.object.get("h") orelse return RouterError.InvalidResponse;
    const caps = parsed.value.object.get("caps") orelse return RouterError.InvalidResponse;
    if (h != .integer or caps != .object) return RouterError.InvalidResponse;
    const rd = caps.object.get("rd") orelse return RouterError.InvalidResponse;
    const wr = caps.object.get("wr") orelse return RouterError.InvalidResponse;
    if (rd != .bool or wr != .bool) return RouterError.InvalidResponse;
    return .{
        .endpoint_index = endpoint_index,
        .handle_id = @intCast(h.integer),
        .node_id = node_id,
        .readable = rd.bool,
        .writable = wr.bool,
    };
}

fn parseCreateResult(json: []const u8, endpoint_index: u16) !OpenFile {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const h = parsed.value.object.get("h") orelse return RouterError.InvalidResponse;
    const attr = parsed.value.object.get("attr") orelse return RouterError.InvalidResponse;
    if (h != .integer or attr != .object) return RouterError.InvalidResponse;
    const id_val = attr.object.get("id") orelse return RouterError.InvalidResponse;
    if (id_val != .integer) return RouterError.InvalidResponse;
    return .{
        .endpoint_index = endpoint_index,
        .handle_id = @intCast(h.integer),
        .node_id = @intCast(id_val.integer),
        .readable = true,
        .writable = true,
    };
}

const ReadResult = struct {
    data: []u8,
    eof: bool,
};

fn parseReadResult(allocator: std.mem.Allocator, json: []const u8) !ReadResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;

    const data_b64 = parsed.value.object.get("data_b64") orelse return RouterError.InvalidResponse;
    const eof = parsed.value.object.get("eof") orelse return RouterError.InvalidResponse;
    if (data_b64 != .string or eof != .bool) return RouterError.InvalidResponse;

    return .{
        .data = try decodeBase64(allocator, data_b64.string),
        .eof = eof.bool,
    };
}

fn parseWriteResult(json: []const u8) !u32 {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const n = parsed.value.object.get("n") orelse return RouterError.InvalidResponse;
    if (n != .integer or n.integer < 0) return RouterError.InvalidResponse;
    return @intCast(n.integer);
}

fn parseGetxattrResult(allocator: std.mem.Allocator, json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;

    const value_b64 = parsed.value.object.get("value_b64") orelse return RouterError.InvalidResponse;
    if (value_b64 != .string) return RouterError.InvalidResponse;
    return decodeBase64(allocator, value_b64.string);
}

fn parseListxattrResult(allocator: std.mem.Allocator, json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return RouterError.InvalidResponse;
    const names_v = parsed.value.object.get("names") orelse return RouterError.InvalidResponse;
    if (names_v != .array) return RouterError.InvalidResponse;

    var total_len: usize = 0;
    for (names_v.array.items) |entry| {
        if (entry != .string) return RouterError.InvalidResponse;
        total_len = std.math.add(usize, total_len, entry.string.len + 1) catch return RouterError.InvalidResponse;
    }

    const out = try allocator.alloc(u8, total_len);
    var cursor: usize = 0;
    for (names_v.array.items) |entry| {
        @memcpy(out[cursor .. cursor + entry.string.len], entry.string);
        cursor += entry.string.len;
        out[cursor] = 0;
        cursor += 1;
    }
    return out;
}

fn encodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out_len = std.base64.standard.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, out_len);
    _ = std.base64.standard.Encoder.encode(out, data);
    return out;
}

fn decodeBase64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(data);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, data);
    return out;
}

test "fs_router: writable requirement matcher handles optional readonly metadata" {
    try std.testing.expect(endpointMatchesWriteRequirement(null, false));
    try std.testing.expect(endpointMatchesWriteRequirement(false, false));
    try std.testing.expect(endpointMatchesWriteRequirement(true, false));

    try std.testing.expect(endpointMatchesWriteRequirement(null, true));
    try std.testing.expect(endpointMatchesWriteRequirement(false, true));
    try std.testing.expect(!endpointMatchesWriteRequirement(true, true));
}

test "fs_router: cross-endpoint move decision maps readonly distinctly" {
    try std.testing.expectEqual(
        @as(CrossEndpointMoveDecision, .allowed),
        decideCrossEndpointMove(.{ .read_only = false }, .{ .read_only = false }),
    );
    try std.testing.expectEqual(
        @as(CrossEndpointMoveDecision, .read_only),
        decideCrossEndpointMove(.{ .read_only = true }, .{ .read_only = false }),
    );
    try std.testing.expectEqual(
        @as(CrossEndpointMoveDecision, .read_only),
        decideCrossEndpointMove(.{ .read_only = false }, .{ .read_only = true }),
    );
}

test "fs_router: flagsRequireWrite detects write access flags" {
    try std.testing.expect(!flagsRequireWrite(0));
    try std.testing.expect(flagsRequireWrite(1));
    try std.testing.expect(flagsRequireWrite(2));
    try std.testing.expect(!flagsRequireWrite(3));
}

test "fs_router: pickExportInfo parses source metadata" {
    const allocator = std.testing.allocator;
    const payload =
        \\{"exports":[
        \\ {"name":"work","root":111,"ro":false,"source_kind":"linux","source_id":"linux:work","caps":{"native_watch":true,"case_sensitive":true}},
        \\ {"name":"drive","root":222,"ro":true,"source_kind":"gdrive","source_id":"gdrive:team","caps":{"native_watch":false,"case_sensitive":true}}
        \\]}
    ;

    var selected = try pickExportInfo(allocator, payload, "drive");
    defer selected.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 222), selected.root_id);
    try std.testing.expectEqual(true, selected.read_only.?);
    try std.testing.expect(selected.source_kind != null);
    try std.testing.expect(selected.source_id != null);
    try std.testing.expect(selected.native_watch != null);
    try std.testing.expect(selected.case_sensitive != null);
    try std.testing.expectEqualStrings("gdrive", selected.source_kind.?);
    try std.testing.expectEqualStrings("gdrive:team", selected.source_id.?);
    try std.testing.expectEqual(false, selected.native_watch.?);
    try std.testing.expectEqual(true, selected.case_sensitive.?);
}

test "fs_router: splitParentChild handles nested path" {
    const split = try splitParentChild("/a/src/main.zig");
    try std.testing.expectEqualStrings("/a/src", split.parent_path);
    try std.testing.expectEqualStrings("main.zig", split.name);
}

test "fs_router: splitParentChild supports root children and rejects root itself" {
    const child = try splitParentChild("/main.zig");
    try std.testing.expectEqualStrings("/", child.parent_path);
    try std.testing.expectEqualStrings("main.zig", child.name);

    try std.testing.expectError(RouterError.InvalidPath, splitParentChild("/"));
    try std.testing.expectError(RouterError.InvalidPath, splitParentChild("/main.zig/"));
}

test "fs_router: normalizeNameForCache honors case sensitivity" {
    const allocator = std.testing.allocator;
    const strict = try normalizeNameForCache(allocator, true, "ReadMe.TXT");
    defer allocator.free(strict);
    try std.testing.expectEqualStrings("ReadMe.TXT", strict);

    const folded = try normalizeNameForCache(allocator, false, "ReadMe.TXT");
    defer allocator.free(folded);
    try std.testing.expectEqualStrings("readme.txt", folded);
}

test "fs_router: case-only rename guard applies on case-insensitive sources" {
    try std.testing.expect(!isCaseOnlyRenameGuard(true, true, "README.md", "readme.md"));
    try std.testing.expect(!isCaseOnlyRenameGuard(false, false, "README.md", "readme.md"));
    try std.testing.expect(isCaseOnlyRenameGuard(false, true, "README.md", "readme.md"));
}

test "fs_router: matchPathToMount handles exact and nested paths" {
    const root = matchPathToMount("/a", "/a") orelse return error.TestExpectedResult;
    try std.testing.expectEqual(@as(usize, 2), root.mount_path_len);
    try std.testing.expectEqualStrings("", root.relative_path);

    const nested = matchPathToMount("/a/src/main.zig", "/a") orelse return error.TestExpectedResult;
    try std.testing.expectEqual(@as(usize, 2), nested.mount_path_len);
    try std.testing.expectEqualStrings("src/main.zig", nested.relative_path);

    try std.testing.expect(matchPathToMount("/abc", "/a") == null);
}

test "fs_router: childSegmentForVirtualDir returns next mount component" {
    try std.testing.expectEqualStrings("project", childSegmentForVirtualDir("/", "/project/src") orelse return error.TestExpectedResult);
    try std.testing.expectEqualStrings("src", childSegmentForVirtualDir("/project", "/project/src") orelse return error.TestExpectedResult);
    try std.testing.expect(childSegmentForVirtualDir("/project/src", "/project/src") == null);
}

test "fs_router: virtualDirNodeId stays within signed integer range" {
    const node_id = virtualDirNodeId("/agents");
    try std.testing.expect(node_id > 0);
    try std.testing.expect(node_id <= std.math.maxInt(i64));
}

test "fs_router: virtual directory listing reflects mount prefixes" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "n1"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/project/src"),
        .root_node_id = 10,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "n2"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65534/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/docs"),
        .root_node_id = 20,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });

    const root_listing = try router.readdir("/", 0, 100);
    defer allocator.free(root_listing);
    try std.testing.expect(std.mem.indexOf(u8, root_listing, "\"name\":\"project\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, root_listing, "\"name\":\"docs\"") != null);

    const project_attr = try router.getattr("/project");
    defer allocator.free(project_attr);
    try std.testing.expect(std.mem.indexOf(u8, project_attr, "\"k\":2") != null);
}

test "fs_router: virtual directories handle trailing slashes" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "caps-node"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/agents/self/capabilities"),
        .root_node_id = 10,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "meta-node"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65534/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/projects/system/meta"),
        .root_node_id = 20,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });

    try std.testing.expect(router.isVirtualDirectoryPath("/agents/"));
    try std.testing.expect(router.isVirtualDirectoryPath("/projects/"));

    const agents_attr = try router.getattr("/agents/");
    defer allocator.free(agents_attr);
    try std.testing.expect(std.mem.indexOf(u8, agents_attr, "\"k\":2") != null);

    const agents_listing = try router.readdir("/agents/", 0, 100);
    defer allocator.free(agents_listing);
    try std.testing.expect(std.mem.indexOf(u8, agents_listing, "\"name\":\"self\"") != null);

    const projects_listing = try router.readdir("/projects/", 0, 100);
    defer allocator.free(projects_listing);
    try std.testing.expect(std.mem.indexOf(u8, projects_listing, "\"name\":\"system\"") != null);
}

test "fs_router: root path is not virtual when an endpoint is mounted at slash" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "root-node"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/"),
        .root_node_id = 42,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });

    try std.testing.expect(!router.isVirtualDirectoryPath("/"));
}

test "fs_router: resolvePath honors explicit mount_path overlays" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "src-node"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/project/src"),
        .root_node_id = 10,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });

    const attr = "{\"id\":101,\"k\":1,\"m\":33188}";
    try router.dir_cache.put(0, 10, "main.zig", 101, attr, now);
    try router.attr_cache.put(.{ .endpoint_index = 0, .node_id = 101 }, attr, 0, now);

    const resolved = try router.resolvePath("/project/src/main.zig", false, .read_data);
    try std.testing.expectEqual(@as(u16, 0), resolved.endpoint_index);
    try std.testing.expectEqual(@as(u64, 101), resolved.node_id);
    try std.testing.expectError(RouterError.UnknownEndpoint, router.resolvePath("/project/main.zig", false, .read_data));
}

test "fs_router: lookupChild treats missing entry as negative when full readdir cache is present" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "root-node"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/"),
        .root_node_id = 1,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });
    try router.dir_complete_cache.markComplete(.{ .endpoint_index = 0, .node_id = 1 }, now);

    try std.testing.expectError(RouterError.FileNotFound, router.lookupChild(0, 1, "bar"));
    try std.testing.expect(router.negative_cache.containsFresh(0, 1, "bar", now));
}

test "fs_router: resolvePath allows advanced ops before source metadata hydration" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "fresh"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/a"),
        .root_node_id = 10,
        .export_read_only = false,
        .source_kind = null,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });

    const attr = "{\"id\":101,\"k\":1,\"m\":33188}";
    try router.dir_cache.put(0, 10, "foo", 101, attr, now);
    try router.attr_cache.put(.{ .endpoint_index = 0, .node_id = 101 }, attr, 0, now);

    const resolved = try router.resolvePath("/a/foo", false, .xattr);
    try std.testing.expectEqual(@as(u16, 0), resolved.endpoint_index);
    try std.testing.expectEqual(@as(u64, 101), resolved.node_id);
}

test "fs_router: parseAttrSummary detects kind from explicit kind and mode bits" {
    const explicit_dir = try parseAttrSummary("{\"id\":1,\"k\":2,\"m\":16877}");
    try std.testing.expectEqual(@as(AttrKind, .dir), explicit_dir.kind);
    try std.testing.expectEqual(@as(u32, 16877), explicit_dir.mode);

    const inferred_file = try parseAttrSummary("{\"id\":2,\"m\":33188}");
    try std.testing.expectEqual(@as(AttrKind, .file), inferred_file.kind);
    try std.testing.expectEqual(@as(u32, 33188), inferred_file.mode);
}

test "fs_router: parseGetxattrResult decodes payload" {
    const allocator = std.testing.allocator;
    const out = try parseGetxattrResult(allocator, "{\"value_b64\":\"aGVsbG8=\"}");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello", out);
}

test "fs_router: parseListxattrResult builds nul separated names" {
    const allocator = std.testing.allocator;
    const out = try parseListxattrResult(allocator, "{\"names\":[\"user.a\",\"user.b\"]}");
    defer allocator.free(out);
    try std.testing.expectEqual(@as(usize, "user.a".len + 1 + "user.b".len + 1), out.len);
    try std.testing.expectEqualStrings("user.a", out[0.."user.a".len]);
    try std.testing.expectEqual(@as(u8, 0), out["user.a".len]);
}

test "fs_router: mapErrno covers xattr and lock errnos" {
    try std.testing.expect(mapErrno(fs_protocol.Errno.ENODATA) == RouterError.NoData);
    try std.testing.expect(mapErrno(fs_protocol.Errno.EAGAIN) == RouterError.WouldBlock);
    try std.testing.expect(mapErrno(fs_protocol.Errno.ERANGE) == RouterError.Range);
    try std.testing.expect(mapErrno(fs_protocol.Errno.ENOSYS) == RouterError.OperationNotSupported);
}

test "fs_router: response retry policy only retries idempotent operations" {
    try std.testing.expect(shouldRetryEndpointErrnoAfterReconnect(.READ, fs_protocol.Errno.EIO));
    try std.testing.expect(shouldRetryEndpointErrnoAfterReconnect(.GETATTR, fs_protocol.Errno.ETIMEDOUT));
    try std.testing.expect(!shouldRetryEndpointErrnoAfterReconnect(.WRITE, fs_protocol.Errno.EIO));
    try std.testing.expect(!shouldRetryEndpointErrnoAfterReconnect(.RENAME, fs_protocol.Errno.EIO));
    try std.testing.expect(!shouldRetryEndpointErrnoAfterReconnect(.READ, fs_protocol.Errno.ENOENT));
}

test "fs_router: endpointRoutingScore prefers healthy endpoints with recent success" {
    var healthy_name = [_]u8{'a'};
    var healthy_url = [_]u8{'u'};
    var degraded_name = [_]u8{'a'};
    var degraded_url = [_]u8{'u'};
    const now = std.time.milliTimestamp();

    const healthy = Endpoint{
        .name = healthy_name[0..],
        .url = healthy_url[0..],
        .export_name = null,
        .mount_path = @constCast("/a"),
        .root_node_id = 1,
        .export_read_only = false,
        .source_kind = @constCast("linux"),
        .caps_case_sensitive = true,
        .healthy = true,
        .last_success_ms = now,
        .last_failure_ms = 0,
        .consecutive_failures = 0,
    };
    const degraded = Endpoint{
        .name = degraded_name[0..],
        .url = degraded_url[0..],
        .export_name = null,
        .mount_path = @constCast("/a"),
        .root_node_id = 1,
        .export_read_only = false,
        .source_kind = @constCast("linux"),
        .caps_case_sensitive = true,
        .healthy = false,
        .last_success_ms = 0,
        .last_failure_ms = now,
        .consecutive_failures = 4,
    };

    const healthy_score = endpointRoutingScore(healthy, .read_data, false, now);
    const degraded_score = endpointRoutingScore(degraded, .read_data, false, now);
    try std.testing.expect(healthy_score > degraded_score);
}

test "fs_router: endpointRoutingScore penalizes capability mismatch" {
    var linux_name = [_]u8{'a'};
    var linux_url = [_]u8{'u'};
    var gdrive_name = [_]u8{'a'};
    var gdrive_url = [_]u8{'u'};
    const now = std.time.milliTimestamp();

    const linux_ep = Endpoint{
        .name = linux_name[0..],
        .url = linux_url[0..],
        .export_name = null,
        .mount_path = @constCast("/a"),
        .root_node_id = 1,
        .export_read_only = false,
        .source_kind = @constCast("linux"),
        .caps_case_sensitive = true,
        .healthy = true,
        .last_success_ms = now,
    };
    const gdrive_ep = Endpoint{
        .name = gdrive_name[0..],
        .url = gdrive_url[0..],
        .export_name = null,
        .mount_path = @constCast("/a"),
        .root_node_id = 1,
        .export_read_only = false,
        .source_kind = @constCast("gdrive"),
        .caps_case_sensitive = true,
        .healthy = true,
        .last_success_ms = now,
    };

    const linux_score = endpointRoutingScore(linux_ep, .xattr, false, now);
    const gdrive_score = endpointRoutingScore(gdrive_ep, .xattr, false, now);
    try std.testing.expect(linux_score > gdrive_score);
}

test "fs_router: endpoint failure classifier covers transport and protocol errors" {
    try std.testing.expect(isEndpointFailureError(error.ConnectionClosed));
    try std.testing.expect(isEndpointFailureError(error.HandshakeRejected));
    try std.testing.expect(isEndpointFailureError(error.ConnectionRefused));
    try std.testing.expect(!isEndpointFailureError(error.OutOfMemory));
}

test "fs_router: statusJson renders empty endpoint list" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const status = try router.statusJson(false);
    defer allocator.free(status);
    try std.testing.expectEqualStrings("{\"metrics\":{\"failover_events_total\":0},\"endpoints\":[]}", status);
}

test "fs_router: applyInvalidationEvent clears affected caches" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    try router.attr_cache.put(.{ .endpoint_index = 0, .node_id = 42 }, "{\"id\":42}", 0, 1000);
    try router.dir_cache.put(0, 77, "x", 42, "{\"id\":42}", 1000);
    try router.dir_listing_cache.put(.{ .endpoint_index = 0, .node_id = 77 }, "{\"ents\":[],\"next_cookie\":0}", 1000);
    try router.dir_complete_cache.markComplete(.{ .endpoint_index = 0, .node_id = 77 }, 1000);
    try router.dir_prime_cache.markComplete(.{ .endpoint_index = 0, .node_id = 77 }, 1000);
    try router.negative_cache.put(0, 77, "missing", 1000);
    try router.read_cache.put(.{ .endpoint_index = 0, .handle_id = 9, .block_index = 0 }, "data");

    router.applyInvalidationEvent(0, .{
        .INVAL = .{
            .node = 42,
            .what = .data,
            .gen = null,
        },
    });

    try std.testing.expect(router.attr_cache.getFresh(.{ .endpoint_index = 0, .node_id = 42 }, 1000) == null);
    try std.testing.expect(router.read_cache.get(.{ .endpoint_index = 0, .handle_id = 9, .block_index = 0 }) == null);

    router.applyInvalidationEvent(0, .{
        .INVAL_DIR = .{
            .dir = 77,
            .dir_gen = null,
        },
    });

    try std.testing.expect(router.dir_cache.getFresh(0, 77, "x", 1000) == null);
    try std.testing.expect(router.dir_listing_cache.getFresh(.{ .endpoint_index = 0, .node_id = 77 }, 1000) == null);
    try std.testing.expect(!router.dir_complete_cache.isFresh(.{ .endpoint_index = 0, .node_id = 77 }, 1000));
    try std.testing.expect(!router.dir_prime_cache.isFresh(.{ .endpoint_index = 0, .node_id = 77 }, 1000));
    try std.testing.expect(!router.negative_cache.containsFresh(0, 77, "missing", 1000));
}

test "fs_router: queued invalidations apply on drain" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    try router.attr_cache.put(.{ .endpoint_index = 0, .node_id = 22 }, "{\"id\":22}", 0, 1000);
    try std.testing.expect(router.attr_cache.getFresh(.{ .endpoint_index = 0, .node_id = 22 }, 1000) != null);

    var ctx = Router.EventDispatchContext{
        .router = &router,
        .endpoint_index = 0,
    };
    Router.handleClientEvent(
        @ptrCast(&ctx),
        .{
            .INVAL = .{
                .node = 22,
                .what = .attr,
                .gen = null,
            },
        },
    );

    try std.testing.expect(router.attr_cache.getFresh(.{ .endpoint_index = 0, .node_id = 22 }, 1000) != null);
    router.drainPendingInvalidations();
    try std.testing.expect(router.attr_cache.getFresh(.{ .endpoint_index = 0, .node_id = 22 }, 1000) == null);
}

test "fs_router: invalidation plus endpoint failure falls back to sibling alias" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "a"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/a"),
        .root_node_id = 10,
        .export_read_only = false,
        .caps_native_watch = true,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "a"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65534/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/a"),
        .root_node_id = 20,
        .export_read_only = false,
        .caps_native_watch = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now - 1_000,
    });

    // Seed both endpoints with cached LOOKUP results for /a/foo.
    const attr_primary = "{\"id\":101,\"k\":1,\"m\":33188}";
    const attr_secondary = "{\"id\":201,\"k\":1,\"m\":33188}";
    try router.dir_cache.put(0, 10, "foo", 101, attr_primary, now);
    try router.attr_cache.put(.{ .endpoint_index = 0, .node_id = 101 }, attr_primary, 0, now);
    try router.dir_cache.put(1, 20, "foo", 201, attr_secondary, now);
    try router.attr_cache.put(.{ .endpoint_index = 1, .node_id = 201 }, attr_secondary, 0, now);

    const before = try router.resolvePath("/a/foo", false, .read_data);
    try std.testing.expectEqual(@as(u16, 0), before.endpoint_index);
    try std.testing.expectEqual(@as(u64, 101), before.node_id);

    // Invalidate endpoint 0 directory cache and mark it failed, then ensure routing
    // falls back to endpoint 1 for the same alias/path.
    router.queueInvalidation(0, .{
        .INVAL_DIR = .{
            .dir = 10,
            .dir_gen = null,
        },
    });
    router.drainPendingInvalidations();
    try std.testing.expect(router.dir_cache.getFresh(0, 10, "foo", now) == null);

    router.noteEndpointFailure(0);
    const after = try router.resolvePath("/a/foo", false, .read_data);
    try std.testing.expectEqual(@as(u16, 1), after.endpoint_index);
    try std.testing.expectEqual(@as(u64, 201), after.node_id);
    try std.testing.expectEqual(@as(u64, 1), router.failover_events_total);
}

test "fs_router: replaceEndpoints swaps mount topology and clears caches" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator, &[_]EndpointConfig{});
    defer router.deinit();

    const now = std.time.milliTimestamp();
    try router.endpoints.append(allocator, .{
        .name = try allocator.dupe(u8, "a"),
        .url = try allocator.dupe(u8, "ws://127.0.0.1:65535/v2/fs"),
        .export_name = null,
        .mount_path = try allocator.dupe(u8, "/a"),
        .root_node_id = 10,
        .export_read_only = false,
        .caps_case_sensitive = true,
        .healthy = true,
        .last_health_check_ms = now,
        .last_success_ms = now,
    });
    try router.dir_cache.put(0, 10, "foo", 123, "{\"id\":123}", now);
    try router.dir_listing_cache.put(.{ .endpoint_index = 0, .node_id = 10 }, "{\"ents\":[],\"next_cookie\":0}", now);
    try router.dir_complete_cache.markComplete(.{ .endpoint_index = 0, .node_id = 10 }, now);
    try router.dir_prime_cache.markComplete(.{ .endpoint_index = 0, .node_id = 10 }, now);
    try std.testing.expect(router.dir_cache.getFresh(0, 10, "foo", now) != null);
    try std.testing.expect(router.dir_listing_cache.getFresh(.{ .endpoint_index = 0, .node_id = 10 }, now) != null);
    try std.testing.expect(router.dir_complete_cache.isFresh(.{ .endpoint_index = 0, .node_id = 10 }, now));
    try std.testing.expect(router.dir_prime_cache.isFresh(.{ .endpoint_index = 0, .node_id = 10 }, now));

    try router.replaceEndpoints(&[_]EndpointConfig{
        .{ .name = "b", .url = "ws://127.0.0.1:65534/v2/fs", .mount_path = "/b" },
    });

    try std.testing.expectEqual(@as(usize, 1), router.endpointCount());
    try std.testing.expectEqualStrings("/b", router.endpointMountPath(0).?);
    try std.testing.expect(router.dir_cache.getFresh(0, 10, "foo", now) == null);
    try std.testing.expect(router.dir_listing_cache.getFresh(.{ .endpoint_index = 0, .node_id = 10 }, now) == null);
    try std.testing.expect(!router.dir_complete_cache.isFresh(.{ .endpoint_index = 0, .node_id = 10 }, now));
    try std.testing.expect(!router.dir_prime_cache.isFresh(.{ .endpoint_index = 0, .node_id = 10 }, now));
}
