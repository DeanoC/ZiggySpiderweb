const std = @import("std");
const builtin = @import("builtin");
const fs_protocol = @import("fs_protocol.zig");
const fs_source_adapter = @import("fs_source_adapter.zig");
const fs_source_adapter_factory = @import("fs_source_adapter_factory.zig");
const fs_local_source_adapter = @import("fs_local_source_adapter.zig");
const fs_windows_source_adapter = @import("fs_windows_source_adapter.zig");
const fs_gdrive_backend = @import("fs_gdrive_backend.zig");
const credential_store = @import("credential_store.zig");

const node_id_export_shift: u6 = 48;
const node_id_export_mask: u64 = 0xFFFF_0000_0000_0000;
const node_id_inode_mask: u64 = 0x0000_FFFF_FFFF_FFFF;
const gdrive_status_name: []const u8 = ".gdrive-status.txt";
const gdrive_poll_interval_ms: u64 = 2_000;
const gdrive_backoff_ms: u64 = 10_000;
const gdrive_spool_dir_env_var: []const u8 = "SPIDERWEB_GDRIVE_SPOOL_DIR";
const gdrive_spool_limit_env_var: []const u8 = "SPIDERWEB_GDRIVE_SPOOL_MAX_BYTES";
const gdrive_spool_default_dir: []const u8 = "/tmp/spiderweb-gdrive-spool";
const gdrive_spool_file_prefix: []const u8 = "spiderweb-gdrive-spool-";
const gdrive_spool_file_suffix: []const u8 = ".tmp";
const gdrive_spool_default_limit_bytes: u64 = 512 * 1024 * 1024;
const namespace_protocol_json =
    "{\"channel\":\"fsrpc\",\"version\":\"styx-lite-1\",\"ops\":[\"t_version\",\"t_attach\",\"t_walk\",\"t_open\",\"t_read\",\"t_write\",\"t_stat\",\"t_clunk\",\"t_flush\"]}";
const namespace_chat_help_md =
    "# Chat Capability\n\n" ++
    "Write UTF-8 text to `control/input` to create a chat job.\n" ++
    "Read `/jobs/<job-id>/result.txt` for assistant output.\n";
const namespace_chat_schema_json =
    "{\"name\":\"chat\",\"input\":\"control/input\",\"jobs\":\"/jobs\",\"result\":\"result.txt\"}";
const namespace_chat_meta_json =
    "{\"name\":\"chat\",\"version\":\"1\",\"agent_id\":\"system\",\"cost_hint\":\"provider-dependent\",\"latency_hint\":\"seconds\"}";

const max_read_bytes: u32 = 1024 * 1024;
const max_write_bytes: usize = 1024 * 1024;

pub const ExportSpec = struct {
    name: []const u8,
    path: []const u8,
    ro: bool = false,
    desc: ?[]const u8 = null,
    source_kind: ?fs_source_adapter.SourceKind = null,
    source_id: ?[]const u8 = null,
    gdrive_credential_handle: ?[]const u8 = null,
    native_watch: ?bool = null,
    case_sensitive: ?bool = null,
};

const ExportConfig = struct {
    adapter: fs_source_adapter.SourceAdapter,
    name: []u8,
    root_path: []u8,
    ro: bool,
    desc: []u8,
    root_node_id: u64,
    source_kind: fs_source_adapter.SourceKind,
    source_id: []u8,
    gdrive_credential_handle: ?[]u8,
    native_watch: bool,
    case_sensitive: bool,
};

const GdriveOauthState = struct {
    client_id: []u8,
    client_secret: []u8,
    refresh_token: []u8,
    access_token: ?[]u8,
    expires_at_ms: u64,

    fn deinit(self: *GdriveOauthState, allocator: std.mem.Allocator) void {
        allocator.free(self.client_id);
        allocator.free(self.client_secret);
        allocator.free(self.refresh_token);
        if (self.access_token) |token| allocator.free(token);
        self.* = undefined;
    }
};

const GdriveAuthState = struct {
    export_index: usize,
    credential_handle: ?[]u8,
    access_token: ?[]u8,
    oauth: ?GdriveOauthState,

    fn deinit(self: *GdriveAuthState, allocator: std.mem.Allocator) void {
        if (self.credential_handle) |handle| allocator.free(handle);
        if (self.access_token) |token| allocator.free(token);
        if (self.oauth) |*oauth| oauth.deinit(allocator);
        self.* = undefined;
    }
};

const GdriveChangeState = struct {
    page_token: ?[]u8 = null,
    last_poll_ms: u64 = 0,
    backoff_until_ms: u64 = 0,
    persist_key: ?[]u8 = null,
    persisted_loaded: bool = false,

    fn deinit(self: *GdriveChangeState, allocator: std.mem.Allocator) void {
        if (self.page_token) |token| allocator.free(token);
        if (self.persist_key) |key| allocator.free(key);
        self.* = undefined;
    }
};

const HandleCaps = struct {
    rd: bool = true,
    wr: bool = false,
};

const OpenHandle = struct {
    file: std.fs.File,
    export_index: usize,
    node_id: u64,
    caps: HandleCaps,
    generation: u64,
};

const GdriveOpenHandle = struct {
    export_index: usize,
    node_id: u64,
    generation: u64,
    kind: enum {
        status,
        file,
    } = .file,
};

const GdriveWriteHandle = struct {
    export_index: usize,
    node_id: u64,
    file_id: []u8,
    parent_node_id: ?u64,
    parent_file_id: ?[]u8,
    expected_generation: u64,
    caps: HandleCaps,
    staging_path: []u8,
    staging_file: std.fs.File,
    staging_len: u64,
    dirty: bool = false,

    fn deinit(self: *GdriveWriteHandle, allocator: std.mem.Allocator) void {
        self.staging_file.close();
        std.fs.deleteFileAbsolute(self.staging_path) catch {};
        allocator.free(self.staging_path);
        allocator.free(self.file_id);
        if (self.parent_file_id) |parent_file_id| allocator.free(parent_file_id);
        self.* = undefined;
    }
};

const NamespaceNodeKind = enum {
    file,
    dir,
};

const NamespaceNode = struct {
    id: u64,
    parent_id: ?u64,
    name: []u8,
    path: []u8,
    kind: NamespaceNodeKind,
    generation: u64,
    writable: bool,
    content: []u8,
    children: std.StringHashMapUnmanaged(u64) = .{},

    fn deinit(self: *NamespaceNode, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
        allocator.free(self.content);
        self.children.deinit(allocator);
        self.* = undefined;
    }
};

const NamespaceExport = struct {
    role: []u8,
    root_id: u64,
    next_inode: u64 = 1,
    nodes: std.AutoHashMapUnmanaged(u64, NamespaceNode) = .{},
    path_to_node: std.StringHashMapUnmanaged(u64) = .{},

    fn deinit(self: *NamespaceExport, allocator: std.mem.Allocator) void {
        allocator.free(self.role);
        var it = self.nodes.valueIterator();
        while (it.next()) |node| node.deinit(allocator);
        self.nodes.deinit(allocator);
        self.path_to_node.deinit(allocator);
        self.* = undefined;
    }
};

const NamespaceOpenHandle = struct {
    export_index: usize,
    node_id: u64,
    caps: HandleCaps,
};

const GdriveNode = struct {
    export_index: usize,
    parent_node_id: ?u64,
    parent_file_id: ?[]u8,
    file_id: []u8,
    name: []u8,
    mime_type: []u8,
    is_dir: bool,
    size: u64,
    mtime_ns: i64,
    generation: u64,

    fn deinit(self: *GdriveNode, allocator: std.mem.Allocator) void {
        if (self.parent_file_id) |parent_file_id| allocator.free(parent_file_id);
        allocator.free(self.file_id);
        allocator.free(self.name);
        allocator.free(self.mime_type);
        self.* = undefined;
    }
};

pub const DispatchResult = struct {
    err_no: i32 = fs_protocol.Errno.SUCCESS,
    err_msg: []const u8 = "",
    result_json: ?[]u8 = null,

    pub fn deinit(self: *DispatchResult, allocator: std.mem.Allocator) void {
        if (self.result_json) |value| allocator.free(value);
        self.* = undefined;
    }

    fn success(result_json: []u8) DispatchResult {
        return .{ .result_json = result_json };
    }

    fn failure(err_no: i32, err_msg: []const u8) DispatchResult {
        return .{
            .err_no = err_no,
            .err_msg = err_msg,
        };
    }
};

const NodeContext = struct {
    node_id: u64,
    export_index: usize,
    path: []const u8,
};

const SourceLookupResult = struct {
    resolved_path: []u8,
    stat: std.fs.File.Stat,
};

const SourceOpenResult = struct {
    file: std.fs.File,
    stat: std.fs.File.Stat,
};

const SourceLockMode = enum {
    shared,
    exclusive,
    unlock,
};

const WatchNodeKind = enum {
    file,
    directory,
    symlink,
};

const WatchedNode = struct {
    parent_id: ?u64,
    kind: WatchNodeKind,
    mtime: i128,
    size: u64,
};

pub const NodeOps = struct {
    allocator: std.mem.Allocator,
    credentials: credential_store.CredentialStore,
    exports: std.ArrayListUnmanaged(ExportConfig) = .{},
    node_paths: std.AutoHashMapUnmanaged(u64, []u8) = .{},
    handles: std.AutoHashMapUnmanaged(u64, OpenHandle) = .{},
    namespace_handles: std.AutoHashMapUnmanaged(u64, NamespaceOpenHandle) = .{},
    namespace_exports: std.AutoHashMapUnmanaged(usize, NamespaceExport) = .{},
    gdrive_handles: std.AutoHashMapUnmanaged(u64, GdriveOpenHandle) = .{},
    gdrive_write_handles: std.AutoHashMapUnmanaged(u64, GdriveWriteHandle) = .{},
    gdrive_nodes: std.AutoHashMapUnmanaged(u64, GdriveNode) = .{},
    gdrive_auth: std.AutoHashMapUnmanaged(usize, GdriveAuthState) = .{},
    gdrive_changes: std.AutoHashMapUnmanaged(usize, GdriveChangeState) = .{},
    gdrive_backend_enabled: bool = false,
    gdrive_env_access_token: ?[]u8 = null,
    gdrive_spool_dir: ?[]u8 = null,
    gdrive_spool_max_bytes: u64 = gdrive_spool_default_limit_bytes,
    gdrive_spool_bytes_in_use: u64 = 0,
    next_handle_id: u64 = 1,
    uid: u32 = 0,
    gid: u32 = 0,
    pending_events: std.ArrayListUnmanaged(fs_protocol.InvalidationEvent) = .{},
    watch_snapshot: std.AutoHashMapUnmanaged(u64, WatchedNode) = .{},
    watch_initialized: bool = false,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, specs: []const ExportSpec) !NodeOps {
        const gdrive_enabled = fs_gdrive_backend.backendEnabled(allocator);
        const gdrive_token = if (gdrive_enabled) fs_gdrive_backend.readAccessToken(allocator) else null;
        var self = NodeOps{
            .allocator = allocator,
            .credentials = credential_store.CredentialStore.init(allocator),
            .uid = detectUid(),
            .gid = detectGid(),
            .gdrive_backend_enabled = gdrive_enabled,
            .gdrive_env_access_token = gdrive_token,
            .gdrive_spool_dir = null,
            .gdrive_spool_max_bytes = resolveGdriveSpoolLimit(allocator),
        };
        errdefer self.deinit();

        if (specs.len == 0) {
            const default_spec = ExportSpec{
                .name = "work",
                .path = ".",
                .ro = false,
                .desc = "workspace root",
            };
            try self.addExport(default_spec);
        } else {
            for (specs) |spec| try self.addExport(spec);
        }
        if (hasGdriveExports(self.exports.items)) {
            self.gdrive_spool_dir = try resolveGdriveSpoolDirForExports(allocator, self.exports.items);
            try self.cleanupGdriveSpoolOrphans();
        }

        return self;
    }

    pub fn deinit(self: *NodeOps) void {
        var node_it = self.node_paths.valueIterator();
        while (node_it.next()) |path| self.allocator.free(path.*);
        self.node_paths.deinit(self.allocator);

        var handle_it = self.handles.valueIterator();
        while (handle_it.next()) |handle| handle.file.close();
        self.handles.deinit(self.allocator);
        self.namespace_handles.deinit(self.allocator);
        var namespace_it = self.namespace_exports.valueIterator();
        while (namespace_it.next()) |ns_export| ns_export.deinit(self.allocator);
        self.namespace_exports.deinit(self.allocator);
        self.gdrive_handles.deinit(self.allocator);
        var gdrive_write_it = self.gdrive_write_handles.valueIterator();
        while (gdrive_write_it.next()) |handle| {
            self.releaseGdriveSpool(handle.staging_len);
            handle.deinit(self.allocator);
        }
        self.gdrive_write_handles.deinit(self.allocator);
        var gdrive_it = self.gdrive_nodes.valueIterator();
        while (gdrive_it.next()) |node| node.deinit(self.allocator);
        self.gdrive_nodes.deinit(self.allocator);
        var gdrive_auth_it = self.gdrive_auth.valueIterator();
        while (gdrive_auth_it.next()) |auth| auth.deinit(self.allocator);
        self.gdrive_auth.deinit(self.allocator);
        var gdrive_changes_it = self.gdrive_changes.valueIterator();
        while (gdrive_changes_it.next()) |state| state.deinit(self.allocator);
        self.gdrive_changes.deinit(self.allocator);
        if (self.gdrive_env_access_token) |token| self.allocator.free(token);
        if (self.gdrive_spool_dir) |path| self.allocator.free(path);

        for (self.exports.items) |*export_cfg| {
            export_cfg.adapter.deinit(self.allocator);
            self.allocator.free(export_cfg.name);
            self.allocator.free(export_cfg.root_path);
            self.allocator.free(export_cfg.desc);
            self.allocator.free(export_cfg.source_id);
            if (export_cfg.gdrive_credential_handle) |handle| self.allocator.free(handle);
        }
        self.exports.deinit(self.allocator);
        self.pending_events.deinit(self.allocator);
        self.watch_snapshot.deinit(self.allocator);
    }

    pub fn dispatch(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.pending_events.clearRetainingCapacity();

        return self.dispatchLocked(req);
    }

    pub fn copyPendingEvents(self: *const NodeOps, allocator: std.mem.Allocator) ![]fs_protocol.InvalidationEvent {
        return allocator.dupe(fs_protocol.InvalidationEvent, self.pending_events.items);
    }

    pub fn pollFilesystemInvalidations(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        max_events: usize,
    ) ![]fs_protocol.InvalidationEvent {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.pollFilesystemInvalidationsLocked(allocator, max_events);
    }

    fn dispatchLocked(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        if (self.rejectUnimplementedSourceRequest(req)) |reject| return reject;

        return switch (req.op) {
            .HELLO => self.opHello(req),
            .EXPORTS => self.opExports(req),
            .LOOKUP => self.opLookup(req),
            .GETATTR => self.opGetattr(req),
            .READDIRP => self.opReaddirPlus(req),
            .SYMLINK => self.opSymlink(req),
            .SETXATTR => self.opSetxattr(req),
            .GETXATTR => self.opGetxattr(req),
            .LISTXATTR => self.opListxattr(req),
            .REMOVEXATTR => self.opRemovexattr(req),
            .OPEN => self.opOpen(req),
            .READ => self.opRead(req),
            .CLOSE => self.opClose(req),
            .LOCK => self.opLock(req),
            .CREATE => self.opCreate(req),
            .WRITE => self.opWrite(req),
            .TRUNCATE => self.opTruncate(req),
            .UNLINK => self.opUnlink(req),
            .MKDIR => self.opMkdir(req),
            .RMDIR => self.opRmdir(req),
            .RENAME => self.opRename(req),
            .STATFS => self.opStatfs(req),
            .INVAL, .INVAL_DIR => DispatchResult.failure(fs_protocol.Errno.EINVAL, "event op is not a request"),
        };
    }

    pub fn exportByName(self: *const NodeOps, name: []const u8) ?usize {
        for (self.exports.items, 0..) |export_cfg, idx| {
            if (std.mem.eql(u8, export_cfg.name, name)) return idx;
        }
        return null;
    }

    pub fn copyExportRootPaths(self: *const NodeOps, allocator: std.mem.Allocator) ![][]u8 {
        const roots = try allocator.alloc([]u8, self.exports.items.len);
        errdefer allocator.free(roots);

        var built: usize = 0;
        errdefer {
            for (roots[0..built]) |path| allocator.free(path);
        }

        for (self.exports.items) |export_cfg| {
            roots[built] = try allocator.dupe(u8, export_cfg.root_path);
            built += 1;
        }
        return roots;
    }

    fn rejectUnimplementedSourceRequest(self: *NodeOps, req: fs_protocol.ParsedRequest) ?DispatchResult {
        const has_unimplemented_export = self.hasPartiallyImplementedSourceExport();
        if (!has_unimplemented_export) return null;

        return switch (req.op) {
            .HELLO, .EXPORTS, .STATFS, .INVAL, .INVAL_DIR => null,
            .READ, .WRITE, .CLOSE, .LOCK => blk: {
                const handle_id = req.handle orelse break :blk null;
                if (self.gdrive_handles.get(handle_id)) |gdrive_handle| {
                    break :blk self.unimplementedForExport(gdrive_handle.export_index, req.op);
                }
                if (self.handles.get(handle_id)) |handle| {
                    break :blk self.unimplementedForExport(handle.export_index, req.op);
                }
                break :blk null;
            },
            .RENAME => blk: {
                const old_parent_id = fs_protocol.getOptionalU64(req.args, "old_parent", 0) catch break :blk null;
                const new_parent_id = fs_protocol.getOptionalU64(req.args, "new_parent", 0) catch break :blk null;
                if (old_parent_id != 0) {
                    if (self.unimplementedForNode(old_parent_id, req.op)) |reject| break :blk reject;
                }
                if (new_parent_id != 0) {
                    if (self.unimplementedForNode(new_parent_id, req.op)) |reject| break :blk reject;
                }
                break :blk null;
            },
            else => blk: {
                const node_id = req.node orelse break :blk null;
                break :blk self.unimplementedForNode(node_id, req.op);
            },
        };
    }

    fn hasPartiallyImplementedSourceExport(self: *const NodeOps) bool {
        const check_ops = [_]fs_source_adapter.Operation{
            .lookup,
            .getattr,
            .readdirp,
            .open,
            .read,
            .close,
            .create,
            .write,
            .truncate,
            .unlink,
            .mkdir,
            .rmdir,
            .rename,
            .statfs,
            .symlink,
            .setxattr,
            .getxattr,
            .listxattr,
            .removexattr,
            .lock,
        };
        for (self.exports.items) |export_cfg| {
            for (check_ops) |op| {
                if (!export_cfg.adapter.supportsOperation(op)) return true;
            }
        }
        return false;
    }

    fn unimplementedForNode(self: *const NodeOps, node_id: u64, op: fs_protocol.Op) ?DispatchResult {
        const export_index = self.exportIndexFromNodeId(node_id) orelse return null;
        return self.unimplementedForExport(export_index, op);
    }

    fn unimplementedForExport(self: *const NodeOps, export_index: usize, op: fs_protocol.Op) ?DispatchResult {
        if (export_index >= self.exports.items.len) return null;
        const source_op = sourceOperationForProtocolOp(op) orelse return null;
        if (self.exports.items[export_index].adapter.supportsOperation(source_op)) return null;
        return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");
    }

    fn exportIndexFromNodeId(self: *const NodeOps, node_id: u64) ?usize {
        _ = self;
        const export_tag = (node_id & node_id_export_mask) >> node_id_export_shift;
        if (export_tag == 0) return null;
        const export_index = export_tag - 1;
        return @intCast(export_index);
    }

    fn addExport(self: *NodeOps, spec: ExportSpec) !void {
        if (spec.name.len == 0) return error.InvalidExportName;
        if (self.exportByName(spec.name) != null) return error.DuplicateExport;

        const source_kind = spec.source_kind orelse fs_source_adapter.defaultSourceKindForHost();
        var source_adapter = try fs_source_adapter_factory.create(self.allocator, source_kind);
        errdefer source_adapter.deinit(self.allocator);
        const prepared = source_adapter.prepareExport(self.allocator, spec.path) catch return error.InvalidExportPath;
        errdefer self.allocator.free(prepared.root_real_path);

        const export_index = self.exports.items.len;
        const root_node_id = makeNodeId(export_index, prepared.root_inode);
        const name = try self.allocator.dupe(u8, spec.name);
        errdefer self.allocator.free(name);
        const desc = try self.allocator.dupe(u8, spec.desc orelse spec.path);
        errdefer self.allocator.free(desc);
        const source_id = if (spec.source_id) |raw|
            try self.allocator.dupe(u8, raw)
        else
            try std.fmt.allocPrint(
                self.allocator,
                "{s}:{s}",
                .{ source_kind.asString(), spec.name },
            );
        errdefer self.allocator.free(source_id);
        const gdrive_credential_handle = if (source_kind == .gdrive)
            if (spec.gdrive_credential_handle) |raw_handle|
                try self.allocator.dupe(u8, raw_handle)
            else
                try defaultGdriveCredentialHandle(self.allocator, spec.name)
        else
            null;
        errdefer if (gdrive_credential_handle) |handle| self.allocator.free(handle);
        const native_watch = spec.native_watch orelse prepared.default_caps.native_watch;
        const case_sensitive = spec.case_sensitive orelse prepared.default_caps.case_sensitive;
        const export_ro = spec.ro;

        try self.exports.append(self.allocator, .{
            .adapter = source_adapter,
            .name = name,
            .root_path = prepared.root_real_path,
            .ro = export_ro,
            .desc = desc,
            .root_node_id = root_node_id,
            .source_kind = source_kind,
            .source_id = source_id,
            .gdrive_credential_handle = gdrive_credential_handle,
            .native_watch = native_watch,
            .case_sensitive = case_sensitive,
        });

        try self.setNodePath(root_node_id, prepared.root_real_path);
        if (source_kind == .gdrive) {
            self.ensureGdriveScaffoldNodes(export_index) catch return error.InvalidExportPath;
            self.initializeGdriveAuth(export_index) catch {};
        } else if (source_kind == .namespace) {
            self.ensureNamespaceScaffold(export_index) catch return error.InvalidExportPath;
        }
    }

    fn ensureGdriveScaffoldNodes(self: *NodeOps, export_index: usize) !void {
        if (export_index >= self.exports.items.len) return error.FileNotFound;
        const export_cfg = self.exports.items[export_index];
        if (export_cfg.source_kind != .gdrive) return;

        const status_id = self.gdriveStatusNodeId(export_index);
        const status_path = try std.fs.path.join(self.allocator, &.{ export_cfg.root_path, gdrive_status_name });
        defer self.allocator.free(status_path);
        try self.setNodePath(status_id, status_path);

        const root_file_id = fs_gdrive_backend.normalizeRootId(self.gdriveRootPathId(export_cfg.root_path));
        self.registerGdriveNode(
            export_index,
            export_cfg.root_node_id,
            null,
            null,
            .{
                .id = root_file_id,
                .name = "/",
                .mime_type = "application/vnd.google-apps.folder",
                .primary_parent_id = null,
                .size = 0,
                .mtime_ns = 0,
                .generation = export_cfg.root_node_id,
                .is_dir = true,
            },
        ) catch {};
    }

    fn ensureNamespaceScaffold(self: *NodeOps, export_index: usize) !void {
        if (export_index >= self.exports.items.len) return error.FileNotFound;
        const export_cfg = self.exports.items[export_index];
        if (export_cfg.source_kind != .namespace) return;

        var ns = NamespaceExport{
            .role = try self.allocator.dupe(u8, export_cfg.source_id),
            .root_id = export_cfg.root_node_id,
            .next_inode = 1,
        };
        errdefer ns.deinit(self.allocator);

        const root = NamespaceNode{
            .id = export_cfg.root_node_id,
            .parent_id = null,
            .name = try self.allocator.dupe(u8, "/"),
            .path = try self.allocator.dupe(u8, "/"),
            .kind = .dir,
            .generation = export_cfg.root_node_id,
            .writable = std.mem.eql(u8, export_cfg.source_id, "jobs"),
            .content = try self.allocator.dupe(u8, ""),
        };
        try ns.nodes.put(self.allocator, root.id, root);
        const root_path_ref = ns.nodes.getPtr(root.id).?.path;
        try ns.path_to_node.put(self.allocator, root_path_ref, root.id);
        try self.setNodePath(root.id, root_path_ref);

        if (std.mem.eql(u8, export_cfg.source_id, "meta")) {
            _ = try self.namespaceCreateNode(export_index, &ns, root.id, "protocol.json", .file, false, namespace_protocol_json);
        } else if (std.mem.eql(u8, export_cfg.source_id, "capabilities")) {
            const chat_dir = try self.namespaceCreateNode(export_index, &ns, root.id, "chat", .dir, false, "");
            _ = try self.namespaceCreateNode(export_index, &ns, chat_dir, "help.md", .file, false, namespace_chat_help_md);
            _ = try self.namespaceCreateNode(export_index, &ns, chat_dir, "schema.json", .file, false, namespace_chat_schema_json);
            _ = try self.namespaceCreateNode(export_index, &ns, chat_dir, "meta.json", .file, false, namespace_chat_meta_json);
            const examples_dir = try self.namespaceCreateNode(export_index, &ns, chat_dir, "examples", .dir, false, "");
            _ = try self.namespaceCreateNode(export_index, &ns, examples_dir, "send.txt", .file, false, "hello from fsrpc chat");
            const control_dir = try self.namespaceCreateNode(export_index, &ns, chat_dir, "control", .dir, true, "");
            _ = try self.namespaceCreateNode(export_index, &ns, control_dir, "input", .file, true, "");
        }

        if (try self.namespace_exports.fetchPut(self.allocator, export_index, ns)) |existing| {
            var replaced = existing.value;
            replaced.deinit(self.allocator);
        }
    }

    fn namespaceCreateNode(
        self: *NodeOps,
        export_index: usize,
        ns: *NamespaceExport,
        parent_id: u64,
        name: []const u8,
        kind: NamespaceNodeKind,
        writable: bool,
        content: []const u8,
    ) !u64 {
        if (!isValidChildName(name)) return error.InvalidArgument;
        const parent = ns.nodes.get(parent_id) orelse return error.FileNotFound;
        if (parent.kind != .dir) return error.NotDir;
        if (parent.children.get(name) != null) return error.PathAlreadyExists;

        const node_id = try self.namespaceAllocNodeId(export_index, ns);
        const path = try namespaceJoinPath(self.allocator, parent.path, name);
        errdefer self.allocator.free(path);

        const node = NamespaceNode{
            .id = node_id,
            .parent_id = parent_id,
            .name = try self.allocator.dupe(u8, name),
            .path = path,
            .kind = kind,
            .generation = node_id,
            .writable = writable,
            .content = try self.allocator.dupe(u8, content),
        };
        try ns.nodes.put(self.allocator, node_id, node);
        errdefer {
            if (ns.nodes.fetchRemove(node_id)) |removed| {
                var orphan = removed.value;
                orphan.deinit(self.allocator);
            }
        }

        const child = ns.nodes.get(node_id).?;
        try ns.path_to_node.put(self.allocator, child.path, node_id);

        var parent_ptr = ns.nodes.getPtr(parent_id) orelse return error.FileNotFound;
        try parent_ptr.children.put(self.allocator, child.name, node_id);
        try self.setNodePath(node_id, child.path);
        return node_id;
    }

    fn namespaceAllocNodeId(
        self: *const NodeOps,
        export_index: usize,
        ns: *NamespaceExport,
    ) !u64 {
        var attempts: usize = 0;
        while (attempts < 1_000_000) : (attempts += 1) {
            ns.next_inode +%= 1;
            if (ns.next_inode == 0) ns.next_inode = 1;
            const candidate = makeNodeId(export_index, ns.next_inode);
            if (!ns.nodes.contains(candidate)) return candidate;
        }
        _ = self;
        return error.OutOfMemory;
    }

    fn namespaceExportFor(self: *NodeOps, export_index: usize) ?*NamespaceExport {
        return self.namespace_exports.getPtr(export_index);
    }

    fn namespaceBumpGeneration(self: *NodeOps, ns: *NamespaceExport, node_id: u64) void {
        _ = self;
        const node = ns.nodes.getPtr(node_id) orelse return;
        node.generation +%= 1;
        if (node.generation == 0) node.generation = 1;
    }

    fn buildNamespaceAttrJson(self: *NodeOps, node: NamespaceNode) ![]u8 {
        const is_dir = node.kind == .dir;
        const mode: u32 = if (is_dir)
            if (node.writable) 0o040755 else 0o040555
        else if (node.writable)
            0o100644
        else
            0o100444;
        const kind_code: u8 = if (is_dir) 2 else 1;
        const nlink: u32 = if (is_dir) 2 else 1;
        const size: u64 = if (is_dir) 0 else @intCast(node.content.len);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"k\":{d},\"m\":{d},\"n\":{d},\"u\":{d},\"g\":{d},\"sz\":{d},\"at\":{d},\"mt\":{d},\"ct\":{d},\"gen\":{d}}}",
            .{ node.id, kind_code, mode, nlink, self.uid, self.gid, size, @as(i64, 0), @as(i64, 0), @as(i64, 0), node.generation },
        );
    }

    fn namespaceUpdateNodePathRecursive(
        self: *NodeOps,
        ns: *NamespaceExport,
        node_id: u64,
        new_path: []const u8,
    ) !void {
        var child_ids = std.ArrayListUnmanaged(u64){};
        defer child_ids.deinit(self.allocator);

        {
            const node = ns.nodes.getPtr(node_id) orelse return error.FileNotFound;
            const old_path = node.path;
            const replacement = if (!std.mem.eql(u8, old_path, new_path))
                try self.allocator.dupe(u8, new_path)
            else
                null;
            _ = ns.path_to_node.fetchRemove(old_path);
            if (replacement) |owned| {
                node.path = owned;
                self.allocator.free(old_path);
            }

            try ns.path_to_node.put(self.allocator, node.path, node_id);
            try self.setNodePath(node_id, node.path);

            var child_it = node.children.valueIterator();
            while (child_it.next()) |child_id| {
                try child_ids.append(self.allocator, child_id.*);
            }
        }

        for (child_ids.items) |child_id| {
            const child = ns.nodes.get(child_id) orelse continue;
            const child_path = try namespaceJoinPath(self.allocator, new_path, child.name);
            defer self.allocator.free(child_path);
            try self.namespaceUpdateNodePathRecursive(ns, child_id, child_path);
        }
    }

    fn namespaceRemoveNodeRecursive(
        self: *NodeOps,
        ns: *NamespaceExport,
        node_id: u64,
    ) !void {
        var child_ids = std.ArrayListUnmanaged(u64){};
        defer child_ids.deinit(self.allocator);

        const node = ns.nodes.get(node_id) orelse return error.FileNotFound;
        var child_it = node.children.valueIterator();
        while (child_it.next()) |child_id| {
            try child_ids.append(self.allocator, child_id.*);
        }

        for (child_ids.items) |child_id| {
            try self.namespaceRemoveNodeRecursive(ns, child_id);
        }

        if (ns.nodes.fetchRemove(node_id)) |removed| {
            var owned = removed.value;
            _ = ns.path_to_node.fetchRemove(owned.path);
            if (self.node_paths.fetchRemove(node_id)) |existing| {
                self.allocator.free(existing.value);
            }
            owned.deinit(self.allocator);
        }
    }

    fn namespaceIsAncestorOf(ns: *const NamespaceExport, ancestor_id: u64, node_id: u64) bool {
        var cursor: ?u64 = node_id;
        while (cursor) |current| {
            if (current == ancestor_id) return true;
            const node = ns.nodes.get(current) orelse return false;
            cursor = node.parent_id;
        }
        return false;
    }

    fn opNamespaceLookup(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const ns = self.namespaceExportFor(parent.export_index) orelse {
            return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        };
        const parent_node = ns.nodes.get(parent.node_id) orelse {
            return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        };
        if (parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");

        const child_id: u64 = if (std.mem.eql(u8, name, "."))
            parent.node_id
        else if (std.mem.eql(u8, name, ".."))
            parent_node.parent_id orelse parent.node_id
        else
            parent_node.children.get(name) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const child = ns.nodes.get(child_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        self.setNodePath(child.id, child.path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildNamespaceAttrJson(child) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceGetattr(self: *NodeOps, ctx: NodeContext) DispatchResult {
        const ns = self.namespaceExportFor(ctx.export_index) orelse {
            return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        };
        const node = ns.nodes.get(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        self.setNodePath(node.id, node.path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildNamespaceAttrJson(node) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceReaddirPlus(self: *NodeOps, ctx: NodeContext, cookie: u64, max_entries: u32) DispatchResult {
        const ns = self.namespaceExportFor(ctx.export_index) orelse {
            return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        };
        const dir_node = ns.nodes.get(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (dir_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");

        const ChildEntry = struct {
            name: []u8,
            node_id: u64,
        };

        var child_entries = std.ArrayListUnmanaged(ChildEntry){};
        defer {
            for (child_entries.items) |entry| self.allocator.free(entry.name);
            child_entries.deinit(self.allocator);
        }

        var child_it = dir_node.children.iterator();
        while (child_it.next()) |entry| {
            const name_copy = self.allocator.dupe(u8, entry.key_ptr.*) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            child_entries.append(self.allocator, .{
                .name = name_copy,
                .node_id = entry.value_ptr.*,
            }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        }
        std.sort.pdq(
            ChildEntry,
            child_entries.items,
            {},
            struct {
                fn lessThan(_: void, lhs: ChildEntry, rhs: ChildEntry) bool {
                    return std.mem.lessThan(u8, lhs.name, rhs.name);
                }
            }.lessThan,
        );

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(self.allocator);
        payload.appendSlice(self.allocator, "{\"ents\":[") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        var first = true;
        var emitted: u32 = 0;
        var count: u64 = 0;
        var has_more = false;

        const dotdot_id = dir_node.parent_id orelse ctx.node_id;
        const synthetic_entries = [_]struct { name: []const u8, node_id: u64 }{
            .{ .name = ".", .node_id = ctx.node_id },
            .{ .name = "..", .node_id = dotdot_id },
        };
        for (synthetic_entries) |entry| {
            defer count += 1;
            if (count < cookie) continue;
            if (emitted >= max_entries) {
                has_more = true;
                break;
            }

            const child = ns.nodes.get(entry.node_id) orelse continue;
            const escaped_name = fs_protocol.jsonEscape(self.allocator, entry.name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_name);
            const attr_json = self.buildNamespaceAttrJson(child) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(attr_json);

            if (!first) payload.append(self.allocator, ',') catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            first = false;
            payload.writer(self.allocator).print("{{\"name\":\"{s}\",\"attr\":{s}}}", .{ escaped_name, attr_json }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            emitted += 1;
        }

        if (!has_more) {
            for (child_entries.items) |entry| {
                defer count += 1;
                if (count < cookie) continue;
                if (emitted >= max_entries) {
                    has_more = true;
                    break;
                }

                const child = ns.nodes.get(entry.node_id) orelse continue;
                const escaped_name = fs_protocol.jsonEscape(self.allocator, entry.name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                defer self.allocator.free(escaped_name);
                const attr_json = self.buildNamespaceAttrJson(child) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                defer self.allocator.free(attr_json);

                if (!first) payload.append(self.allocator, ',') catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                first = false;
                payload.writer(self.allocator).print("{{\"name\":\"{s}\",\"attr\":{s}}}", .{ escaped_name, attr_json }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                emitted += 1;
            }
        }

        payload.writer(self.allocator).print(
            "],\"next\":{d},\"eof\":{},\"dir_gen\":{d}}}",
            .{ cookie + emitted, !has_more, dir_node.generation },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        return DispatchResult.success(payload.toOwnedSlice(self.allocator) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory"));
    }

    fn opNamespaceOpen(self: *NodeOps, ctx: NodeContext, node_id: u64, flags: u32) DispatchResult {
        const ns = self.namespaceExportFor(ctx.export_index) orelse {
            return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        };
        const node = ns.nodes.get(node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (node.kind == .dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        const access = accessModeFromFlags(flags);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.ro and access.wr) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (access.wr and !node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        self.namespace_handles.put(self.allocator, handle_id, .{
            .export_index = ctx.export_index,
            .node_id = node_id,
            .caps = .{ .rd = access.rd, .wr = access.wr },
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"h\":{d},\"caps\":{{\"rd\":{},\"wr\":{}}},\"gen\":{d}}}",
            .{ handle_id, access.rd, access.wr, node.generation },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceRead(self: *NodeOps, handle_id: u64, off: u64, len: u32) DispatchResult {
        const handle = self.namespace_handles.get(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (!handle.caps.rd) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not readable");

        const ns = self.namespaceExportFor(handle.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const node = ns.nodes.get(handle.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (node.kind == .dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        const start: usize = std.math.cast(usize, off) orelse node.content.len;
        if (start >= node.content.len) {
            const response = self.allocator.dupe(u8, "{\"data_b64\":\"\",\"eof\":true}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const max_len: usize = len;
        const requested_end = std.math.add(usize, start, max_len) catch std.math.maxInt(usize);
        const end = @min(node.content.len, requested_end);
        const bytes = node.content[start..end];

        const encoded = encodeBase64(self.allocator, bytes) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(encoded);
        const eof = end >= node.content.len;
        const response = std.fmt.allocPrint(self.allocator, "{{\"data_b64\":\"{s}\",\"eof\":{}}}", .{ encoded, eof }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceCreate(self: *NodeOps, parent: NodeContext, name: []const u8, mode: u32, flags: u32) DispatchResult {
        _ = mode;
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(parent.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const parent_node = ns.nodes.get(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        if (!parent_node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const node_id = self.namespaceCreateNode(parent.export_index, ns, parent.node_id, name, .file, true, "") catch |err| return mapError(err);
        self.namespaceBumpGeneration(ns, parent.node_id);
        const node = ns.nodes.get(node_id) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace node missing");

        const access = accessModeFromFlags(flags);
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        self.namespace_handles.put(self.allocator, handle_id, .{
            .export_index = parent.export_index,
            .node_id = node_id,
            .caps = .{ .rd = access.rd, .wr = true },
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildNamespaceAttrJson(node) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s},\"h\":{d}}}", .{ attr_json, handle_id }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = node.generation,
            },
        });
        return DispatchResult.success(response);
    }

    fn opNamespaceWrite(self: *NodeOps, handle_id: u64, off: u64, data_b64: []const u8) DispatchResult {
        const handle = self.namespace_handles.get(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (!handle.caps.wr) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not writable");

        const export_cfg = self.exports.items[handle.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const decoded = decodeBase64(self.allocator, data_b64) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid base64 payload");
        defer self.allocator.free(decoded);
        if (decoded.len > max_write_bytes) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "WRITE exceeds max_write");

        const ns = self.namespaceExportFor(handle.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const node = ns.nodes.getPtr(handle.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (node.kind == .dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");
        if (!node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        if (decoded.len > 0) {
            const off_usize = std.math.cast(usize, off) orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "write offset too large");
            const required_end = std.math.add(usize, off_usize, decoded.len) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "write too large");
            if (required_end > node.content.len) {
                const resized = self.allocator.alloc(u8, required_end) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                if (node.content.len > 0) @memcpy(resized[0..node.content.len], node.content);
                @memset(resized[node.content.len..], 0);
                self.allocator.free(node.content);
                node.content = resized;
            }
            @memcpy(node.content[off_usize .. off_usize + decoded.len], decoded);
            self.namespaceBumpGeneration(ns, node.id);
            self.queueInvalidation(.{
                .INVAL = .{
                    .node = node.id,
                    .what = .data,
                    .gen = node.generation,
                },
            });
        }

        const response = std.fmt.allocPrint(self.allocator, "{{\"n\":{d}}}", .{decoded.len}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceTruncate(self: *NodeOps, ctx: NodeContext, size: u64) DispatchResult {
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(ctx.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const node = ns.nodes.getPtr(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (node.kind == .dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");
        if (!node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const new_len = std.math.cast(usize, size) orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "truncate size too large");
        if (new_len != node.content.len) {
            const resized = self.allocator.alloc(u8, new_len) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            const copy_len = @min(node.content.len, new_len);
            if (copy_len > 0) @memcpy(resized[0..copy_len], node.content[0..copy_len]);
            if (new_len > copy_len) @memset(resized[copy_len..new_len], 0);
            self.allocator.free(node.content);
            node.content = resized;
            self.namespaceBumpGeneration(ns, node.id);
        }

        self.queueInvalidation(.{
            .INVAL = .{
                .node = node.id,
                .what = .all,
                .gen = node.generation,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceUnlink(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(parent.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const parent_node = ns.nodes.get(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        if (!parent_node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const child_id = parent_node.children.get(name) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const child = ns.nodes.get(child_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (child.kind == .dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        {
            const parent_mut = ns.nodes.getPtr(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            _ = parent_mut.children.fetchRemove(name);
        }
        self.namespaceRemoveNodeRecursive(ns, child_id) catch |err| return mapError(err);
        self.namespaceBumpGeneration(ns, parent.node_id);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceMkdir(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(parent.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const parent_node = ns.nodes.get(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        if (!parent_node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        _ = self.namespaceCreateNode(parent.export_index, ns, parent.node_id, name, .dir, true, "") catch |err| return mapError(err);
        self.namespaceBumpGeneration(ns, parent.node_id);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceRmdir(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(parent.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const parent_node = ns.nodes.get(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        if (!parent_node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const child_id = parent_node.children.get(name) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const child = ns.nodes.get(child_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (child.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "not a directory");
        if (child.children.count() != 0) return DispatchResult.failure(fs_protocol.Errno.ENOTEMPTY, "directory not empty");

        {
            const parent_mut = ns.nodes.getPtr(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            _ = parent_mut.children.fetchRemove(name);
        }
        self.namespaceRemoveNodeRecursive(ns, child_id) catch |err| return mapError(err);
        self.namespaceBumpGeneration(ns, parent.node_id);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opNamespaceRename(
        self: *NodeOps,
        old_parent: NodeContext,
        new_parent: NodeContext,
        old_name: []const u8,
        new_name: []const u8,
    ) DispatchResult {
        const export_cfg = self.exports.items[old_parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const ns = self.namespaceExportFor(old_parent.export_index) orelse return DispatchResult.failure(fs_protocol.Errno.EIO, "namespace export missing");
        const old_parent_node = ns.nodes.get(old_parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const new_parent_node = ns.nodes.get(new_parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (old_parent_node.kind != .dir or new_parent_node.kind != .dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        if (!old_parent_node.writable or !new_parent_node.writable) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const moving_id = old_parent_node.children.get(old_name) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (new_parent_node.children.get(new_name) != null) return DispatchResult.failure(fs_protocol.Errno.EEXIST, "path exists");

        if (old_parent.node_id == new_parent.node_id and std.mem.eql(u8, old_name, new_name)) {
            const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const moving_node = ns.nodes.get(moving_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (moving_node.kind == .dir and namespaceIsAncestorOf(ns, moving_id, new_parent.node_id)) {
            return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid rename target");
        }

        const owned_new_name = self.allocator.dupe(u8, new_name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        var new_name_installed = false;
        defer if (!new_name_installed) self.allocator.free(owned_new_name);

        {
            const old_parent_mut = ns.nodes.getPtr(old_parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            _ = old_parent_mut.children.fetchRemove(old_name);
        }

        {
            const moving_mut = ns.nodes.getPtr(moving_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            const old_name_owned = moving_mut.name;
            moving_mut.name = owned_new_name;
            new_name_installed = true;
            self.allocator.free(old_name_owned);
            moving_mut.parent_id = new_parent.node_id;
            self.namespaceBumpGeneration(ns, moving_id);
        }

        {
            const new_parent_mut = ns.nodes.getPtr(new_parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            const moving_now = ns.nodes.get(moving_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            new_parent_mut.children.put(self.allocator, moving_now.name, moving_id) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        }

        const parent_path = (ns.nodes.get(new_parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found")).path;
        const moving_name = (ns.nodes.get(moving_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found")).name;
        const new_path = namespaceJoinPath(self.allocator, parent_path, moving_name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(new_path);
        self.namespaceUpdateNodePathRecursive(ns, moving_id, new_path) catch |err| return mapError(err);

        self.namespaceBumpGeneration(ns, old_parent.node_id);
        self.namespaceBumpGeneration(ns, new_parent.node_id);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = old_parent.node_id,
                .dir_gen = null,
            },
        });
        if (old_parent.node_id != new_parent.node_id) {
            self.queueInvalidation(.{
                .INVAL_DIR = .{
                    .dir = new_parent.node_id,
                    .dir_gen = null,
                },
            });
        }
        self.queueInvalidation(.{
            .INVAL = .{
                .node = moving_id,
                .what = .all,
                .gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn gdriveStatusNodeId(self: *const NodeOps, export_index: usize) u64 {
        const export_cfg = self.exports.items[export_index];
        const root_inode = export_cfg.root_node_id & node_id_inode_mask;
        var inode = std.hash.Wyhash.hash(0x4744_5343_4146_4F4C, export_cfg.source_id) & node_id_inode_mask;
        if (inode == 0 or inode == root_inode) {
            inode = (inode ^ 0x0000_0000_0000_002A) & node_id_inode_mask;
        }
        if (inode == 0 or inode == root_inode) inode = 1;
        if (inode == root_inode) inode = (inode + 1) & node_id_inode_mask;
        if (inode == 0) inode = 2;
        return makeNodeId(export_index, inode);
    }

    fn gdriveStatusContent(self: *NodeOps, export_index: usize) ![]u8 {
        const export_cfg = self.exports.items[export_index];
        const api_mode = if (self.gdrive_backend_enabled) "enabled" else "disabled";
        const auth_mode, const token_state = self.gdriveStatusAuth(export_index);
        return std.fmt.allocPrint(
            self.allocator,
            "Google Drive source\nsource_id: {s}\nstatus: write-enabled\napi_mode: {s}\nauth_mode: {s}\naccess_token: {s}\nimplemented: LOOKUP GETATTR READDIRP OPEN READ CLOSE CREATE WRITE TRUNCATE MKDIR UNLINK RMDIR RENAME\n",
            .{ export_cfg.source_id, api_mode, auth_mode, token_state },
        );
    }

    fn buildSyntheticAttrJson(self: *NodeOps, node_id: u64, is_dir: bool, size: u64, gen: u64, mtime_ns: i64) ![]u8 {
        const mode: u32 = if (is_dir) 0o040755 else 0o100644;
        const kind_code: u8 = if (is_dir) 2 else 1;
        const nlink: u32 = if (is_dir) 2 else 1;
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"k\":{d},\"m\":{d},\"n\":{d},\"u\":{d},\"g\":{d},\"sz\":{d},\"at\":{d},\"mt\":{d},\"ct\":{d},\"gen\":{d}}}",
            .{ node_id, kind_code, mode, nlink, self.uid, self.gid, size, mtime_ns, mtime_ns, mtime_ns, gen },
        );
    }

    fn gdriveRootPathId(self: *const NodeOps, root_path: []const u8) []const u8 {
        _ = self;
        if (!std.mem.startsWith(u8, root_path, "gdrive://")) return "root";
        return root_path["gdrive://".len..];
    }

    fn initializeGdriveAuth(self: *NodeOps, export_index: usize) !void {
        if (!self.gdrive_backend_enabled) return;
        if (self.gdrive_env_access_token) |token| {
            try self.storeGdriveAuthState(export_index, .{
                .export_index = export_index,
                .credential_handle = null,
                .access_token = try self.allocator.dupe(u8, token),
                .oauth = null,
            });
            return;
        }

        if (export_index >= self.exports.items.len) return;
        const export_cfg = self.exports.items[export_index];
        const handle = export_cfg.gdrive_credential_handle orelse return;
        const secret = self.credentials.getProviderApiKey(handle) orelse return;
        defer self.allocator.free(secret);

        if (parseGdriveOauthState(self.allocator, secret)) |oauth| {
            try self.storeGdriveAuthState(export_index, .{
                .export_index = export_index,
                .credential_handle = try self.allocator.dupe(u8, handle),
                .access_token = null,
                .oauth = oauth,
            });
            return;
        } else |_| {}

        if (secret.len == 0) return;
        try self.storeGdriveAuthState(export_index, .{
            .export_index = export_index,
            .credential_handle = try self.allocator.dupe(u8, handle),
            .access_token = try self.allocator.dupe(u8, secret),
            .oauth = null,
        });
    }

    fn storeGdriveAuthState(self: *NodeOps, export_index: usize, state: GdriveAuthState) !void {
        if (try self.gdrive_auth.fetchPut(self.allocator, export_index, state)) |existing| {
            var old = existing.value;
            old.deinit(self.allocator);
        }
    }

    fn gdriveStatusAuth(self: *const NodeOps, export_index: usize) struct { []const u8, []const u8 } {
        if (!self.gdrive_backend_enabled) return .{ "disabled", "missing" };
        if (self.gdrive_env_access_token != null) return .{ "env_access_token", "present" };
        const auth = self.gdrive_auth.get(export_index) orelse return .{ "credential_handle", "missing" };
        if (auth.oauth != null) {
            if (auth.oauth.?.access_token != null) return .{ "oauth_refresh", "present" };
            if (auth.oauth.?.refresh_token.len > 0) return .{ "oauth_refresh", "refresh_only" };
            return .{ "oauth_refresh", "missing" };
        }
        return if (auth.access_token != null) .{ "credential_handle", "present" } else .{ "credential_handle", "missing" };
    }

    fn gdriveTokenForExport(self: *NodeOps, export_index: usize) !?[]const u8 {
        if (!self.gdrive_backend_enabled) return null;
        if (self.gdrive_env_access_token) |token| return token;

        const auth = self.gdrive_auth.getPtr(export_index) orelse return null;
        if (auth.access_token) |token| return token;

        if (auth.oauth) |*oauth| {
            if (oauth.access_token) |token| {
                if (oauth.expires_at_ms > gdriveNowMs() + 60_000) return token;
            }

            var refreshed = try fs_gdrive_backend.refreshAccessToken(
                self.allocator,
                oauth.client_id,
                oauth.client_secret,
                oauth.refresh_token,
            );
            defer refreshed.deinit(self.allocator);

            if (oauth.access_token) |old| self.allocator.free(old);
            oauth.access_token = try self.allocator.dupe(u8, refreshed.access_token);
            oauth.expires_at_ms = refreshed.expires_at_ms;
            if (refreshed.refresh_token) |new_refresh| {
                self.allocator.free(oauth.refresh_token);
                oauth.refresh_token = try self.allocator.dupe(u8, new_refresh);
            }
            self.persistGdriveOauthState(auth) catch {};
            return oauth.access_token;
        }
        return null;
    }

    fn persistGdriveOauthState(self: *NodeOps, auth: *const GdriveAuthState) !void {
        if (!self.credentials.supportsSecureStorage()) return;
        const handle = auth.credential_handle orelse return;
        const oauth = auth.oauth orelse return;
        const serialized = try serializeGdriveOauthState(self.allocator, oauth);
        defer self.allocator.free(serialized);
        self.credentials.setProviderApiKey(handle, serialized) catch {};
    }

    fn ensureGdriveChangeStateLoaded(self: *NodeOps, export_index: usize, state: *GdriveChangeState) void {
        if (state.persisted_loaded) return;
        state.persisted_loaded = true;
        if (!self.credentials.supportsSecureStorage()) return;

        const persist_key = self.buildGdriveChangePersistKey(export_index) catch return;
        state.persist_key = persist_key;
        const key = state.persist_key orelse return;

        const raw = self.credentials.getProviderApiKey(key) orelse return;
        defer self.allocator.free(raw);
        var parsed = parseGdriveChangeStateBundle(self.allocator, raw) catch return;
        defer parsed.deinit(self.allocator);
        if (parsed.page_token.len == 0) return;

        if (state.page_token) |old| self.allocator.free(old);
        state.page_token = self.allocator.dupe(u8, parsed.page_token) catch null;
    }

    fn persistGdriveChangeState(self: *NodeOps, export_index: usize, state: *const GdriveChangeState) void {
        if (!self.credentials.supportsSecureStorage()) return;
        const key = state.persist_key orelse return;
        const token = state.page_token orelse return;
        const serialized = serializeGdriveChangeStateBundle(
            self.allocator,
            self.exports.items[export_index].source_id,
            token,
            gdriveNowMs(),
        ) catch return;
        defer self.allocator.free(serialized);
        self.credentials.setProviderApiKey(key, serialized) catch {};
    }

    fn clearPersistedGdriveChangeState(self: *NodeOps, state: *const GdriveChangeState) void {
        if (!self.credentials.supportsSecureStorage()) return;
        const key = state.persist_key orelse return;
        self.credentials.clearProviderApiKey(key) catch {};
    }

    fn buildGdriveChangePersistKey(self: *NodeOps, export_index: usize) !?[]u8 {
        if (export_index >= self.exports.items.len) return null;
        const export_cfg = self.exports.items[export_index];
        const handle_seed = export_cfg.gdrive_credential_handle orelse export_cfg.source_id;
        return try buildGdriveChangePersistHandle(self.allocator, handle_seed);
    }

    fn gdriveNodeFor(self: *const NodeOps, node_id: u64) ?*const GdriveNode {
        return self.gdrive_nodes.getPtr(node_id);
    }

    fn gdriveNodeForMut(self: *NodeOps, node_id: u64) ?*GdriveNode {
        return self.gdrive_nodes.getPtr(node_id);
    }

    fn gdriveFirstNodeIdForFileId(self: *const NodeOps, export_index: usize, file_id: []const u8) ?u64 {
        var it = self.gdrive_nodes.iterator();
        while (it.next()) |entry| {
            const node = entry.value_ptr.*;
            if (node.export_index != export_index) continue;
            if (!std.mem.eql(u8, node.file_id, file_id)) continue;
            return entry.key_ptr.*;
        }
        return null;
    }

    fn gdriveNodeIdForFile(self: *NodeOps, export_index: usize, file_id: []const u8) u64 {
        const export_cfg = self.exports.items[export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(export_index);
        var attempt: u64 = 0;
        while (true) : (attempt += 1) {
            var inode = std.hash.Wyhash.hash(0x4744_4E4F_4445_0001 +% attempt, file_id) & node_id_inode_mask;
            if (inode == 0) inode = 1;
            const node_id = makeNodeId(export_index, inode);
            if (node_id == root_id or node_id == status_id) continue;
            if (self.gdrive_nodes.get(node_id)) |existing| {
                if (std.mem.eql(u8, existing.file_id, file_id)) return node_id;
                continue;
            }
            return node_id;
        }
    }

    fn gdriveNodePath(self: *NodeOps, export_cfg: ExportConfig, file_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ export_cfg.root_path, file_id });
    }

    fn registerGdriveNode(
        self: *NodeOps,
        export_index: usize,
        node_id: u64,
        parent_node_id: ?u64,
        parent_file_id: ?[]const u8,
        file: anytype,
    ) !void {
        const export_cfg = self.exports.items[export_index];
        const file_id = try self.allocator.dupe(u8, file.id);
        errdefer self.allocator.free(file_id);
        const name = try self.allocator.dupe(u8, file.name);
        errdefer self.allocator.free(name);
        const mime_type = try self.allocator.dupe(u8, file.mime_type);
        errdefer self.allocator.free(mime_type);
        const stored_parent_file_id = if (parent_file_id) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (stored_parent_file_id) |value| self.allocator.free(value);

        const node_path = try self.gdriveNodePath(export_cfg, file.id);
        defer self.allocator.free(node_path);
        try self.setNodePath(node_id, node_path);

        const stored = GdriveNode{
            .export_index = export_index,
            .parent_node_id = parent_node_id,
            .parent_file_id = stored_parent_file_id,
            .file_id = file_id,
            .name = name,
            .mime_type = mime_type,
            .is_dir = file.is_dir,
            .size = file.size,
            .mtime_ns = file.mtime_ns,
            .generation = file.generation,
        };

        if (try self.gdrive_nodes.fetchPut(self.allocator, node_id, stored)) |existing| {
            var old = existing.value;
            old.deinit(self.allocator);
        }
    }

    fn opGdriveLookup(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(parent.export_index);

        if (parent.node_id == status_id) {
            return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
        }
        if (std.mem.eql(u8, name, gdrive_status_name)) {
            if (parent.node_id != root_id) {
                return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            }
            self.ensureGdriveScaffoldNodes(parent.export_index) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            const content = self.gdriveStatusContent(parent.export_index) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(content);
            const attr_json = self.buildSyntheticAttrJson(status_id, false, content.len, status_id, 0) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(attr_json);
            const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const token = self.gdriveTokenForExport(parent.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const parent_file_id = if (parent.node_id == root_id)
            fs_gdrive_backend.normalizeRootId(self.gdriveRootPathId(export_cfg.root_path))
        else blk: {
            const parent_node = self.gdriveNodeFor(parent.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            if (!parent_node.is_dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
            break :blk parent_node.file_id;
        };

        const maybe_file = fs_gdrive_backend.lookupChildByName(
            self.allocator,
            token.?,
            parent_file_id,
            name,
        ) catch |err| return mapError(err);
        var file = maybe_file orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        defer file.deinit(self.allocator);

        const child_id = self.gdriveNodeIdForFile(parent.export_index, file.id);
        self.registerGdriveNode(parent.export_index, child_id, parent.node_id, parent_file_id, file) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildSyntheticAttrJson(child_id, file.is_dir, file.size, file.generation, file.mtime_ns) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGdriveGetattr(self: *NodeOps, ctx: NodeContext) DispatchResult {
        const export_cfg = self.exports.items[ctx.export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(ctx.export_index);

        if (ctx.node_id == root_id) {
            const attr_json = self.buildSyntheticAttrJson(root_id, true, 0, root_id, 0) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(attr_json);
            const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }
        if (ctx.node_id == status_id) {
            const content = self.gdriveStatusContent(ctx.export_index) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(content);
            const attr_json = self.buildSyntheticAttrJson(status_id, false, content.len, status_id, 0) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(attr_json);
            const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const node = self.gdriveNodeForMut(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (self.gdriveTokenForExport(ctx.export_index) catch |err| return mapError(err)) |token| {
            var refreshed = fs_gdrive_backend.statFile(self.allocator, token, node.file_id) catch |err| return mapError(err);
            defer refreshed.deinit(self.allocator);
            const refreshed_parent_file_id = refreshed.primary_parent_id orelse node.parent_file_id;
            const refreshed_parent_node_id = if (refreshed_parent_file_id) |parent_file_id|
                self.gdriveFirstNodeIdForFileId(ctx.export_index, parent_file_id) orelse node.parent_node_id
            else
                node.parent_node_id;
            self.registerGdriveNode(ctx.export_index, ctx.node_id, refreshed_parent_node_id, refreshed_parent_file_id, refreshed) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        }
        const current = self.gdriveNodeFor(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        const attr_json = self.buildSyntheticAttrJson(ctx.node_id, current.is_dir, current.size, current.generation, current.mtime_ns) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    const GdriveDirEntry = struct {
        name: []u8,
        node_id: u64,
        is_dir: bool,
        size: u64,
        generation: u64,
        mtime_ns: i64,
    };

    fn opGdriveReaddirPlus(self: *NodeOps, ctx: NodeContext, cookie: u64, max_entries: u32) DispatchResult {
        const export_cfg = self.exports.items[ctx.export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(ctx.export_index);
        if (ctx.node_id == status_id) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");

        const token = self.gdriveTokenForExport(ctx.export_index) catch |err| return mapError(err);
        const parent_file_id = if (ctx.node_id == root_id)
            fs_gdrive_backend.normalizeRootId(self.gdriveRootPathId(export_cfg.root_path))
        else blk: {
            const node = self.gdriveNodeFor(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            if (!node.is_dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");
            break :blk node.file_id;
        };

        var entries = std.ArrayListUnmanaged(GdriveDirEntry){};
        defer {
            for (entries.items) |entry| self.allocator.free(entry.name);
            entries.deinit(self.allocator);
        }

        const dot_name = self.allocator.dupe(u8, ".") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        entries.append(self.allocator, .{
            .name = dot_name,
            .node_id = ctx.node_id,
            .is_dir = true,
            .size = 0,
            .generation = ctx.node_id,
            .mtime_ns = 0,
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const dotdot_id = if (ctx.node_id == root_id) root_id else blk: {
            const node = self.gdriveNodeFor(ctx.node_id) orelse break :blk root_id;
            break :blk node.parent_node_id orelse root_id;
        };
        const dotdot_name = self.allocator.dupe(u8, "..") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        entries.append(self.allocator, .{
            .name = dotdot_name,
            .node_id = dotdot_id,
            .is_dir = true,
            .size = 0,
            .generation = dotdot_id,
            .mtime_ns = 0,
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        if (ctx.node_id == root_id) {
            const status_content = self.gdriveStatusContent(ctx.export_index) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(status_content);
            const status_name = self.allocator.dupe(u8, gdrive_status_name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            entries.append(self.allocator, .{
                .name = status_name,
                .node_id = status_id,
                .is_dir = false,
                .size = status_content.len,
                .generation = status_id,
                .mtime_ns = 0,
            }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        }

        if (token) |access_token| {
            var listed = fs_gdrive_backend.listChildren(
                self.allocator,
                access_token,
                parent_file_id,
            ) catch |err| return mapError(err);
            defer listed.deinit(self.allocator);

            for (listed.files) |file| {
                if (!isValidChildName(file.name)) continue;
                const child_id = self.gdriveNodeIdForFile(ctx.export_index, file.id);
                const child_parent_file_id = file.primary_parent_id orelse parent_file_id;
                self.registerGdriveNode(ctx.export_index, child_id, ctx.node_id, child_parent_file_id, file) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                const name_copy = self.allocator.dupe(u8, file.name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                entries.append(self.allocator, .{
                    .name = name_copy,
                    .node_id = child_id,
                    .is_dir = file.is_dir,
                    .size = file.size,
                    .generation = file.generation,
                    .mtime_ns = file.mtime_ns,
                }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            }
        }

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(self.allocator);
        payload.appendSlice(self.allocator, "{\"ents\":[") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        var first = true;
        var emitted: u32 = 0;
        var count: u64 = 0;
        var has_more = false;

        for (entries.items) |entry| {
            defer count += 1;
            if (count < cookie) continue;
            if (emitted >= max_entries) {
                has_more = true;
                break;
            }

            const escaped_name = fs_protocol.jsonEscape(self.allocator, entry.name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_name);
            const attr_json = self.buildSyntheticAttrJson(entry.node_id, entry.is_dir, entry.size, entry.generation, entry.mtime_ns) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(attr_json);

            if (!first) payload.append(self.allocator, ',') catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            first = false;
            payload.writer(self.allocator).print("{{\"name\":\"{s}\",\"attr\":{s}}}", .{ escaped_name, attr_json }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            emitted += 1;
        }

        payload.writer(self.allocator).print(
            "],\"next\":{d},\"eof\":{},\"dir_gen\":{d}}}",
            .{ cookie + emitted, !has_more, ctx.node_id },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        return DispatchResult.success(payload.toOwnedSlice(self.allocator) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory"));
    }

    fn createGdriveStagingFile(self: *NodeOps) !struct { path: []u8, file: std.fs.File } {
        const spool_dir = self.gdrive_spool_dir orelse return error.FileNotFound;
        var attempt: u64 = 0;
        while (attempt < 64) : (attempt += 1) {
            const candidate = try std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}{d}-{d}{s}",
                .{ spool_dir, gdrive_spool_file_prefix, std.time.nanoTimestamp(), attempt, gdrive_spool_file_suffix },
            );
            errdefer self.allocator.free(candidate);

            const file = std.fs.createFileAbsolute(candidate, .{
                .read = true,
                .truncate = true,
                .exclusive = true,
            }) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    self.allocator.free(candidate);
                    continue;
                },
                else => return err,
            };
            return .{ .path = candidate, .file = file };
        }
        return error.PathAlreadyExists;
    }

    fn cleanupGdriveSpoolOrphans(self: *NodeOps) !void {
        const spool_dir = self.gdrive_spool_dir orelse return;
        var dir = std.fs.openDirAbsolute(spool_dir, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.startsWith(u8, entry.name, gdrive_spool_file_prefix)) continue;
            if (!std.mem.endsWith(u8, entry.name, gdrive_spool_file_suffix)) continue;
            dir.deleteFile(entry.name) catch {};
        }
    }

    fn reserveGdriveSpool(self: *NodeOps, additional: u64) !void {
        if (additional == 0) return;
        if (self.gdrive_spool_max_bytes == 0) {
            self.gdrive_spool_bytes_in_use = std.math.add(u64, self.gdrive_spool_bytes_in_use, additional) catch return error.GdriveSpoolLimitExceeded;
            return;
        }
        const next = std.math.add(u64, self.gdrive_spool_bytes_in_use, additional) catch return error.GdriveSpoolLimitExceeded;
        if (next > self.gdrive_spool_max_bytes) return error.GdriveSpoolLimitExceeded;
        self.gdrive_spool_bytes_in_use = next;
    }

    fn releaseGdriveSpool(self: *NodeOps, amount: u64) void {
        if (amount >= self.gdrive_spool_bytes_in_use) {
            self.gdrive_spool_bytes_in_use = 0;
            return;
        }
        self.gdrive_spool_bytes_in_use -= amount;
    }

    fn writeZeroFill(file: *std.fs.File, start: u64, end: u64) !void {
        if (end <= start) return;
        var zeros: [4096]u8 = [_]u8{0} ** 4096;
        var cursor = start;
        while (cursor < end) {
            const remaining = end - cursor;
            const chunk_len: usize = @intCast(@min(remaining, zeros.len));
            try file.pwriteAll(zeros[0..chunk_len], cursor);
            cursor += chunk_len;
        }
    }

    fn opGdriveOpen(self: *NodeOps, ctx: NodeContext, node_id: u64, flags: u32) DispatchResult {
        const access = accessModeFromFlags(flags);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.ro and access.wr) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(ctx.export_index);
        if (node_id == root_id) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");
        if (node_id == status_id and access.wr) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;

        if (node_id == status_id) {
            self.gdrive_handles.put(self.allocator, handle_id, .{
                .export_index = ctx.export_index,
                .node_id = node_id,
                .generation = node_id,
                .kind = .status,
            }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            const response = std.fmt.allocPrint(
                self.allocator,
                "{{\"h\":{d},\"caps\":{{\"rd\":true,\"wr\":false}},\"gen\":{d}}}",
                .{ handle_id, node_id },
            ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        } else {
            const node = self.gdriveNodeFor(node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
            if (node.is_dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");
            if (access.wr) {
                const token = self.gdriveTokenForExport(ctx.export_index) catch |err| return mapError(err);
                if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");

                var latest = fs_gdrive_backend.statFile(
                    self.allocator,
                    token.?,
                    node.file_id,
                ) catch |err| return mapError(err);
                defer latest.deinit(self.allocator);
                const refreshed_parent_file_id = latest.primary_parent_id orelse node.parent_file_id;
                const refreshed_parent_node_id = if (refreshed_parent_file_id) |parent_file_id|
                    self.gdriveFirstNodeIdForFileId(ctx.export_index, parent_file_id) orelse node.parent_node_id
                else
                    node.parent_node_id;
                self.registerGdriveNode(ctx.export_index, node_id, refreshed_parent_node_id, refreshed_parent_file_id, latest) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                const current_node = self.gdriveNodeFor(node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");

                const content = fs_gdrive_backend.readFileAll(
                    self.allocator,
                    token.?,
                    current_node.file_id,
                ) catch |err| return mapError(err);
                defer self.allocator.free(content);
                const file_id_copy = self.allocator.dupe(u8, current_node.file_id) catch {
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                };
                const parent_file_copy = if (current_node.parent_file_id) |parent_file_id|
                    self.allocator.dupe(u8, parent_file_id) catch {
                        self.allocator.free(file_id_copy);
                        return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                    }
                else
                    null;
                self.reserveGdriveSpool(content.len) catch |err| return mapError(err);
                var release_reserved = true;
                defer if (release_reserved) self.releaseGdriveSpool(content.len);
                const staging = self.createGdriveStagingFile() catch {
                    self.allocator.free(file_id_copy);
                    if (parent_file_copy) |value| self.allocator.free(value);
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                };
                var staging_file = staging.file;
                const staging_path = staging.path;
                errdefer {
                    staging_file.close();
                    std.fs.deleteFileAbsolute(staging_path) catch {};
                    self.allocator.free(staging_path);
                }
                if (content.len > 0) {
                    staging_file.pwriteAll(content, 0) catch {
                        self.allocator.free(file_id_copy);
                        if (parent_file_copy) |value| self.allocator.free(value);
                        return DispatchResult.failure(fs_protocol.Errno.EIO, "write staging failed");
                    };
                }

                var write_handle = GdriveWriteHandle{
                    .export_index = ctx.export_index,
                    .node_id = node_id,
                    .file_id = file_id_copy,
                    .parent_node_id = current_node.parent_node_id,
                    .parent_file_id = parent_file_copy,
                    .expected_generation = current_node.generation,
                    .caps = .{ .rd = access.rd, .wr = access.wr },
                    .staging_path = staging_path,
                    .staging_file = staging_file,
                    .staging_len = content.len,
                    .dirty = false,
                };
                self.gdrive_write_handles.put(self.allocator, handle_id, write_handle) catch {
                    write_handle.deinit(self.allocator);
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                };
                release_reserved = false;

                const response = std.fmt.allocPrint(
                    self.allocator,
                    "{{\"h\":{d},\"caps\":{{\"rd\":{},\"wr\":{}}},\"gen\":{d}}}",
                    .{ handle_id, access.rd, access.wr, current_node.generation },
                ) catch {
                    if (self.gdrive_write_handles.fetchRemove(handle_id)) |removed| {
                        var orphan = removed.value;
                        self.releaseGdriveSpool(orphan.staging_len);
                        orphan.deinit(self.allocator);
                    }
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                };
                return DispatchResult.success(response);
            }

            self.gdrive_handles.put(self.allocator, handle_id, .{
                .export_index = ctx.export_index,
                .node_id = node_id,
                .generation = node.generation,
                .kind = .file,
            }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            const response = std.fmt.allocPrint(
                self.allocator,
                "{{\"h\":{d},\"caps\":{{\"rd\":true,\"wr\":false}},\"gen\":{d}}}",
                .{ handle_id, node.generation },
            ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }
    }

    fn opGdriveRead(self: *NodeOps, handle_id: u64, off: u64, len: u32) DispatchResult {
        if (self.gdrive_write_handles.get(handle_id)) |handle| {
            if (!handle.caps.rd) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not readable");
            const start = @min(off, handle.staging_len);
            const remaining = handle.staging_len - start;
            const max_len: u64 = len;
            const read_len_u64 = @min(remaining, max_len);
            const read_len: usize = @intCast(read_len_u64);
            const bytes = self.allocator.alloc(u8, read_len) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(bytes);
            if (read_len > 0) {
                const n = handle.staging_file.pread(bytes, start) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "read staging failed");
                if (n != read_len) return DispatchResult.failure(fs_protocol.Errno.EIO, "short staging read");
            }
            const eof = start + read_len_u64 >= handle.staging_len;
            const encoded = encodeBase64(self.allocator, bytes) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(encoded);
            const response = std.fmt.allocPrint(
                self.allocator,
                "{{\"data_b64\":\"{s}\",\"eof\":{}}}",
                .{ encoded, eof },
            ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const handle = self.gdrive_handles.get(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (handle.kind == .status) {
            const content = self.gdriveStatusContent(handle.export_index) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(content);
            const start: usize = if (off >= content.len) content.len else @intCast(off);
            const max_len: usize = @intCast(len);
            const end = @min(content.len, start + max_len);
            const bytes = content[start..end];
            const eof = end >= content.len;
            const encoded = encodeBase64(self.allocator, bytes) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(encoded);
            const response = std.fmt.allocPrint(
                self.allocator,
                "{{\"data_b64\":\"{s}\",\"eof\":{}}}",
                .{ encoded, eof },
            ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        const token = self.gdriveTokenForExport(handle.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");
        const node = self.gdriveNodeFor(handle.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (node.is_dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        const bytes = fs_gdrive_backend.readFileRange(
            self.allocator,
            token.?,
            node.file_id,
            off,
            len,
        ) catch |err| return mapError(err);
        defer self.allocator.free(bytes);

        const encoded = encodeBase64(self.allocator, bytes) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(encoded);
        const eof = (off + bytes.len) >= node.size or bytes.len < len;
        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"data_b64\":\"{s}\",\"eof\":{}}}",
            .{ encoded, eof },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGdriveClose(self: *NodeOps, handle_id: u64) DispatchResult {
        if (self.gdrive_write_handles.fetchRemove(handle_id)) |removed| {
            var write_handle = removed.value;
            defer write_handle.deinit(self.allocator);
            defer self.releaseGdriveSpool(write_handle.staging_len);

            if (write_handle.dirty) {
                const token = self.gdriveTokenForExport(write_handle.export_index) catch |err| return mapError(err);
                if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");

                if (write_handle.expected_generation != 0) {
                    var latest = fs_gdrive_backend.statFile(
                        self.allocator,
                        token.?,
                        write_handle.file_id,
                    ) catch |err| return mapError(err);
                    defer latest.deinit(self.allocator);
                    if (latest.generation != write_handle.expected_generation) {
                        return mapError(error.GdriveConflict);
                    }
                }

                var updated = fs_gdrive_backend.updateFileContentFromFile(
                    self.allocator,
                    token.?,
                    write_handle.file_id,
                    &write_handle.staging_file,
                    write_handle.staging_len,
                ) catch |err| return mapError(err);
                defer updated.deinit(self.allocator);
                write_handle.expected_generation = updated.generation;

                const updated_node_id = self.upsertGdriveFileInCache(
                    write_handle.export_index,
                    write_handle.parent_node_id,
                    write_handle.parent_file_id,
                    updated,
                ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

                const parent_dir = write_handle.parent_node_id orelse self.exports.items[write_handle.export_index].root_node_id;
                self.queueInvalidation(.{
                    .INVAL_DIR = .{
                        .dir = parent_dir,
                        .dir_gen = null,
                    },
                });
                self.queueInvalidation(.{
                    .INVAL = .{
                        .node = updated_node_id,
                        .what = .all,
                        .gen = null,
                    },
                });
            }

            const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        _ = self.gdrive_handles.fetchRemove(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn gdriveParentFileId(self: *NodeOps, parent: NodeContext) ![]const u8 {
        const export_cfg = self.exports.items[parent.export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(parent.export_index);
        if (parent.node_id == status_id) return error.GdriveNotDirectory;
        if (parent.node_id == root_id) {
            return fs_gdrive_backend.normalizeRootId(self.gdriveRootPathId(export_cfg.root_path));
        }

        const parent_node = self.gdriveNodeFor(parent.node_id) orelse return error.FileNotFound;
        if (!parent_node.is_dir) return error.GdriveNotDirectory;
        return parent_node.file_id;
    }

    fn collectGdriveNodeIdsForFileId(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        export_index: usize,
        file_id: []const u8,
    ) ![]u64 {
        var ids = std.ArrayListUnmanaged(u64){};
        errdefer ids.deinit(allocator);

        var it = self.gdrive_nodes.iterator();
        while (it.next()) |entry| {
            const node = entry.value_ptr.*;
            if (node.export_index != export_index) continue;
            if (!std.mem.eql(u8, node.file_id, file_id)) continue;
            try ids.append(allocator, entry.key_ptr.*);
        }
        return ids.toOwnedSlice(allocator);
    }

    fn removeGdriveCachedNodesForFileId(self: *NodeOps, export_index: usize, file_id: []const u8) void {
        var it = self.gdrive_nodes.iterator();
        var ids = std.ArrayListUnmanaged(u64){};
        defer ids.deinit(self.allocator);
        while (it.next()) |entry| {
            const node = entry.value_ptr.*;
            if (node.export_index != export_index) continue;
            if (!std.mem.eql(u8, node.file_id, file_id)) continue;
            ids.append(self.allocator, entry.key_ptr.*) catch continue;
        }

        for (ids.items) |node_id| {
            if (self.gdrive_nodes.fetchRemove(node_id)) |removed| {
                var removed_node = removed.value;
                removed_node.deinit(self.allocator);
            }
            if (self.node_paths.fetchRemove(node_id)) |removed_path| {
                self.allocator.free(removed_path.value);
            }
        }
    }

    fn upsertGdriveFileInCache(
        self: *NodeOps,
        export_index: usize,
        fallback_parent_node_id: ?u64,
        fallback_parent_file_id: ?[]const u8,
        file: fs_gdrive_backend.GdriveFile,
    ) !u64 {
        const resolved_parent_file_id = file.primary_parent_id orelse fallback_parent_file_id;
        const resolved_parent_node_id = if (resolved_parent_file_id) |parent_file_id|
            self.gdriveFirstNodeIdForFileId(export_index, parent_file_id) orelse fallback_parent_node_id
        else
            fallback_parent_node_id;

        const existing_ids = try self.collectGdriveNodeIdsForFileId(self.allocator, export_index, file.id);
        defer self.allocator.free(existing_ids);
        if (existing_ids.len == 0) {
            const node_id = self.gdriveNodeIdForFile(export_index, file.id);
            try self.registerGdriveNode(export_index, node_id, resolved_parent_node_id, resolved_parent_file_id, file);
            return node_id;
        }

        for (existing_ids) |node_id| {
            try self.registerGdriveNode(export_index, node_id, resolved_parent_node_id, resolved_parent_file_id, file);
        }
        return existing_ids[0];
    }

    fn opGdriveMkdir(self: *NodeOps, parent: NodeContext, name: []const u8) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        if (parent.node_id == export_cfg.root_node_id and std.mem.eql(u8, name, gdrive_status_name)) {
            return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        }

        const token = self.gdriveTokenForExport(parent.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");
        const parent_file_id = self.gdriveParentFileId(parent) catch |err| return mapError(err);

        var created = fs_gdrive_backend.createFolder(
            self.allocator,
            token.?,
            parent_file_id,
            name,
        ) catch |err| return mapError(err);
        defer created.deinit(self.allocator);

        const node_id = self.upsertGdriveFileInCache(
            parent.export_index,
            parent.node_id,
            parent_file_id,
            created,
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = null,
            },
        });

        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGdriveCreate(self: *NodeOps, parent: NodeContext, name: []const u8, mode: u32, flags: u32) DispatchResult {
        _ = mode;
        const export_cfg = self.exports.items[parent.export_index];
        if (parent.node_id == export_cfg.root_node_id and std.mem.eql(u8, name, gdrive_status_name)) {
            return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        }

        const token = self.gdriveTokenForExport(parent.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");
        const parent_file_id = self.gdriveParentFileId(parent) catch |err| return mapError(err);

        var created = fs_gdrive_backend.createFile(
            self.allocator,
            token.?,
            parent_file_id,
            name,
        ) catch |err| return mapError(err);
        defer created.deinit(self.allocator);

        const node_id = self.upsertGdriveFileInCache(
            parent.export_index,
            parent.node_id,
            parent_file_id,
            created,
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const access = accessModeFromFlags(flags);
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        const file_id_copy = self.allocator.dupe(u8, created.id) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        const parent_file_copy = self.allocator.dupe(u8, parent_file_id) catch {
            self.allocator.free(file_id_copy);
            return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        };
        const staging = self.createGdriveStagingFile() catch {
            self.allocator.free(parent_file_copy);
            self.allocator.free(file_id_copy);
            return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        };
        var staging_file = staging.file;
        const staging_path = staging.path;
        errdefer {
            staging_file.close();
            std.fs.deleteFileAbsolute(staging_path) catch {};
            self.allocator.free(staging_path);
        }

        var write_handle = GdriveWriteHandle{
            .export_index = parent.export_index,
            .node_id = node_id,
            .file_id = file_id_copy,
            .parent_node_id = parent.node_id,
            .parent_file_id = parent_file_copy,
            .expected_generation = created.generation,
            .caps = .{ .rd = access.rd, .wr = true },
            .staging_path = staging_path,
            .staging_file = staging_file,
            .staging_len = 0,
            .dirty = false,
        };
        self.gdrive_write_handles.put(self.allocator, handle_id, write_handle) catch {
            write_handle.deinit(self.allocator);
            return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        };

        const attr_json = self.buildSyntheticAttrJson(node_id, false, 0, created.generation, created.mtime_ns) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);
        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"attr\":{s},\"h\":{d}}}",
            .{ attr_json, handle_id },
        ) catch {
            if (self.gdrive_write_handles.fetchRemove(handle_id)) |removed| {
                var orphan = removed.value;
                orphan.deinit(self.allocator);
            }
            return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        };

        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = null,
            },
        });
        return DispatchResult.success(response);
    }

    fn opGdriveTruncate(self: *NodeOps, ctx: NodeContext, size: u64) DispatchResult {
        const export_cfg = self.exports.items[ctx.export_index];
        const root_id = export_cfg.root_node_id;
        const status_id = self.gdriveStatusNodeId(ctx.export_index);
        if (ctx.node_id == root_id or ctx.node_id == status_id) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        const node = self.gdriveNodeFor(ctx.node_id) orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        if (node.is_dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");
        const parent_node_id = node.parent_node_id;
        const parent_file_id = node.parent_file_id;

        const token = self.gdriveTokenForExport(ctx.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");

        if (node.generation != 0) {
            var latest = fs_gdrive_backend.statFile(
                self.allocator,
                token.?,
                node.file_id,
            ) catch |err| return mapError(err);
            defer latest.deinit(self.allocator);
            if (latest.generation != node.generation) {
                return mapError(error.GdriveConflict);
            }
        }

        const existing = fs_gdrive_backend.readFileAll(
            self.allocator,
            token.?,
            node.file_id,
        ) catch |err| return mapError(err);
        defer self.allocator.free(existing);

        const desired_len = std.math.cast(usize, size) orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "size too large");
        const next = self.allocator.alloc(u8, desired_len) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(next);
        const preserved = @min(existing.len, desired_len);
        if (preserved > 0) @memcpy(next[0..preserved], existing[0..preserved]);
        if (desired_len > preserved) @memset(next[preserved..], 0);

        var updated = fs_gdrive_backend.updateFileContent(
            self.allocator,
            token.?,
            node.file_id,
            next,
        ) catch |err| return mapError(err);
        defer updated.deinit(self.allocator);

        const updated_node_id = self.upsertGdriveFileInCache(
            ctx.export_index,
            parent_node_id,
            parent_file_id,
            updated,
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const parent_dir = parent_node_id orelse root_id;
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_dir,
                .dir_gen = null,
            },
        });
        self.queueInvalidation(.{
            .INVAL = .{
                .node = updated_node_id,
                .what = .all,
                .gen = null,
            },
        });

        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGdriveDeleteByName(self: *NodeOps, parent: NodeContext, name: []const u8, expect_dir: bool) DispatchResult {
        const export_cfg = self.exports.items[parent.export_index];
        if (parent.node_id == export_cfg.root_node_id and std.mem.eql(u8, name, gdrive_status_name)) {
            return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        }

        const token = self.gdriveTokenForExport(parent.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");
        const parent_file_id = self.gdriveParentFileId(parent) catch |err| return mapError(err);

        const maybe_file = fs_gdrive_backend.lookupChildByName(
            self.allocator,
            token.?,
            parent_file_id,
            name,
        ) catch |err| return mapError(err);
        var file = maybe_file orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        defer file.deinit(self.allocator);

        if (expect_dir and !file.is_dir) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "not a directory");
        if (!expect_dir and file.is_dir) return DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory");

        const node_ids = self.collectGdriveNodeIdsForFileId(
            self.allocator,
            parent.export_index,
            file.id,
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(node_ids);

        fs_gdrive_backend.deleteFile(self.allocator, token.?, file.id) catch |err| return mapError(err);
        self.removeGdriveCachedNodesForFileId(parent.export_index, file.id);

        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent.node_id,
                .dir_gen = null,
            },
        });
        for (node_ids) |node_id| {
            self.queueInvalidation(.{
                .INVAL = .{
                    .node = node_id,
                    .what = .all,
                    .gen = null,
                },
            });
        }

        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGdriveRename(
        self: *NodeOps,
        old_parent: NodeContext,
        new_parent: NodeContext,
        old_name: []const u8,
        new_name: []const u8,
    ) DispatchResult {
        const export_cfg = self.exports.items[old_parent.export_index];
        if (old_parent.node_id == export_cfg.root_node_id and std.mem.eql(u8, old_name, gdrive_status_name)) {
            return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        }
        if (new_parent.node_id == export_cfg.root_node_id and std.mem.eql(u8, new_name, gdrive_status_name)) {
            return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        }

        const token = self.gdriveTokenForExport(old_parent.export_index) catch |err| return mapError(err);
        if (token == null) return DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive api mode disabled or missing token");
        const old_parent_file_id = self.gdriveParentFileId(old_parent) catch |err| return mapError(err);
        const new_parent_file_id = self.gdriveParentFileId(new_parent) catch |err| return mapError(err);

        const maybe_target = fs_gdrive_backend.lookupChildByName(
            self.allocator,
            token.?,
            old_parent_file_id,
            old_name,
        ) catch |err| return mapError(err);
        var target = maybe_target orelse return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        defer target.deinit(self.allocator);

        const move_parent = !std.mem.eql(u8, old_parent_file_id, new_parent_file_id);
        const rename_name = !std.mem.eql(u8, old_name, new_name);
        if (!move_parent and !rename_name) {
            const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        var updated = fs_gdrive_backend.updateFileMetadata(
            self.allocator,
            token.?,
            target.id,
            if (rename_name) new_name else null,
            if (move_parent) new_parent_file_id else null,
            if (move_parent) old_parent_file_id else null,
        ) catch |err| return mapError(err);
        defer updated.deinit(self.allocator);

        const updated_node_id = self.upsertGdriveFileInCache(
            old_parent.export_index,
            if (move_parent) new_parent.node_id else old_parent.node_id,
            if (move_parent) new_parent_file_id else old_parent_file_id,
            updated,
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = old_parent.node_id,
                .dir_gen = null,
            },
        });
        if (old_parent.node_id != new_parent.node_id) {
            self.queueInvalidation(.{
                .INVAL_DIR = .{
                    .dir = new_parent.node_id,
                    .dir_gen = null,
                },
            });
        }
        self.queueInvalidation(.{
            .INVAL = .{
                .node = updated_node_id,
                .what = .all,
                .gen = null,
            },
        });

        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opHello(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        _ = req;
        const hello_caps = self.computeHelloCaps();
        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"protocol\":\"unified-v2-fs\",\"proto\":2,\"node\":{{\"name\":\"spiderweb-fs-node\",\"os\":\"{s}\",\"ver\":\"0.1.0\"}},\"caps\":{{\"readdirp\":true,\"symlink\":{},\"xattr\":{},\"locks\":{},\"case_sensitive\":{},\"max_read\":{d},\"max_write\":{d}}}}}",
            .{
                @tagName(builtin.os.tag),
                hello_caps.symlink,
                hello_caps.xattr,
                hello_caps.locks,
                hello_caps.case_sensitive,
                max_read_bytes,
                max_write_bytes,
            },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opStatfs(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "STATFS requires node");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        const bsize: u64 = if (export_cfg.source_kind == .gdrive) 256 * 1024 else 4096;
        const payload = std.fmt.allocPrint(
            self.allocator,
            "{{\"bsize\":{d},\"frsize\":{d},\"blocks\":{d},\"bfree\":{d},\"bavail\":{d},\"files\":{d},\"ffree\":{d},\"favail\":{d},\"namemax\":{d}}}",
            .{
                bsize,
                bsize,
                @as(u64, 0),
                @as(u64, 0),
                @as(u64, 0),
                @as(u64, 0),
                @as(u64, 0),
                @as(u64, 0),
                @as(u64, 255),
            },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(payload);
    }

    fn computeHelloCaps(self: *const NodeOps) struct {
        symlink: bool,
        xattr: bool,
        locks: bool,
        case_sensitive: bool,
    } {
        var symlink = true;
        var xattr = true;
        var locks = true;
        var case_sensitive = true;

        for (self.exports.items) |export_cfg| {
            const caps = sourceFeatureCaps(export_cfg);
            symlink = symlink and caps.symlink;
            xattr = xattr and caps.xattr;
            locks = locks and caps.locks;
            case_sensitive = case_sensitive and export_cfg.case_sensitive;
        }

        return .{
            .symlink = symlink,
            .xattr = xattr,
            .locks = locks,
            .case_sensitive = case_sensitive,
        };
    }

    fn sourceFeatureCaps(export_cfg: ExportConfig) fs_source_adapter.SourceCaps {
        return export_cfg.adapter.featureCaps();
    }

    fn opExports(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        _ = req;
        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(self.allocator);

        payload.appendSlice(self.allocator, "{\"exports\":[") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        for (self.exports.items, 0..) |export_cfg, idx| {
            if (idx > 0) payload.append(self.allocator, ',') catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

            const escaped_name = fs_protocol.jsonEscape(self.allocator, export_cfg.name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_name);
            const escaped_desc = fs_protocol.jsonEscape(self.allocator, export_cfg.desc) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_desc);
            const escaped_source_kind = fs_protocol.jsonEscape(self.allocator, export_cfg.source_kind.asString()) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_source_kind);
            const escaped_source_id = fs_protocol.jsonEscape(self.allocator, export_cfg.source_id) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            defer self.allocator.free(escaped_source_id);
            const source_caps = sourceFeatureCaps(export_cfg);

            payload.writer(self.allocator).print(
                "{{\"name\":\"{s}\",\"root\":{d},\"ro\":{},\"desc\":\"{s}\",\"source_kind\":\"{s}\",\"source_id\":\"{s}\",\"caps\":{{\"native_watch\":{},\"case_sensitive\":{},\"symlink\":{},\"xattr\":{},\"locks\":{},\"statfs\":{}}}}}",
                .{
                    escaped_name,
                    export_cfg.root_node_id,
                    export_cfg.ro,
                    escaped_desc,
                    escaped_source_kind,
                    escaped_source_id,
                    export_cfg.native_watch,
                    export_cfg.case_sensitive,
                    source_caps.symlink,
                    source_caps.xattr,
                    source_caps.locks,
                    source_caps.statfs,
                },
            ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        }
        payload.appendSlice(self.allocator, "]}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        return DispatchResult.success(payload.toOwnedSlice(self.allocator) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory"));
    }

    fn opLookup(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "LOOKUP requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "LOOKUP requires a.name");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.source_kind == .namespace) {
            return self.opNamespaceLookup(parent, name);
        }
        if (export_cfg.source_kind == .gdrive) {
            return self.opGdriveLookup(parent, name);
        }
        if (isHiddenLocalExportChild(export_cfg.source_kind, name)) {
            return DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found");
        }
        const looked = sourceLookupChildAbsolute(
            export_cfg.source_kind,
            self.allocator,
            export_cfg.root_path,
            parent.path,
            name,
        ) catch |err| return mapError(err);
        defer self.allocator.free(looked.resolved_path);
        const stat = looked.stat;
        const node_id = makeNodeId(parent.export_index, stat.inode);
        self.setNodePath(node_id, looked.resolved_path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildAttrJson(node_id, stat) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);

        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGetattr(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "GETATTR requires node");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .namespace) {
            return self.opNamespaceGetattr(ctx);
        }
        if (export_cfg.source_kind == .gdrive) {
            return self.opGdriveGetattr(ctx);
        }
        const stat = sourceStatAbsolute(export_cfg.source_kind, ctx.path) catch |err| return mapError(err);

        const attr_json = self.buildAttrJson(node_id, stat) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);

        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s}}}", .{attr_json}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opSymlink(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SYMLINK requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SYMLINK requires a.name");
        const target = fs_protocol.getRequiredString(req.args, "target") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SYMLINK requires a.target");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");

        const link_path = std.fs.path.join(self.allocator, &.{ parent.path, name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(link_path);
        if (!isWithinRoot(export_cfg.root_path, link_path)) return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");

        fs_local_source_adapter.symlinkAbsolute(target, link_path) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opSetxattr(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SETXATTR requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SETXATTR requires a.name");
        const value_b64 = fs_protocol.getRequiredString(req.args, "value_b64") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "SETXATTR requires a.value_b64");
        const flags = fs_protocol.getOptionalU32(req.args, "flags", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "flags must be u32");

        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");

        const value = decodeBase64(self.allocator, value_b64) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid base64 payload");
        defer self.allocator.free(value);
        fs_local_source_adapter.setXattrAbsolute(self.allocator, ctx.path, name, value, flags) catch |err| return mapError(err);

        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .attr,
                .gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opGetxattr(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "GETXATTR requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "GETXATTR requires a.name");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .gdrive) return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");

        const value = fs_local_source_adapter.getXattrAbsolute(self.allocator, ctx.path, name) catch |err| return mapError(err);
        defer self.allocator.free(value);
        const encoded = encodeBase64(self.allocator, value) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(encoded);

        const response = std.fmt.allocPrint(self.allocator, "{{\"value_b64\":\"{s}\"}}", .{encoded}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opListxattr(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "LISTXATTR requires node");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .gdrive) return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");

        const raw = fs_local_source_adapter.listXattrAbsolute(self.allocator, ctx.path) catch |err| return mapError(err);
        defer self.allocator.free(raw);

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(self.allocator);
        payload.appendSlice(self.allocator, "{\"names\":[") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        var first = true;
        var idx: usize = 0;
        while (idx < raw.len) {
            const start = idx;
            while (idx < raw.len and raw[idx] != 0) : (idx += 1) {}
            if (idx > start) {
                const name = raw[start..idx];
                const escaped = fs_protocol.jsonEscape(self.allocator, name) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                defer self.allocator.free(escaped);
                if (!first) payload.append(self.allocator, ',') catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
                first = false;
                payload.writer(self.allocator).print("\"{s}\"", .{escaped}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            }
            idx += 1;
        }

        payload.appendSlice(self.allocator, "]}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(payload.toOwnedSlice(self.allocator) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory"));
    }

    fn opRemovexattr(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "REMOVEXATTR requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "REMOVEXATTR requires a.name");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");

        fs_local_source_adapter.removeXattrAbsolute(self.allocator, ctx.path, name) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .attr,
                .gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opReaddirPlus(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const dir_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "READDIRP requires node");
        const cookie = fs_protocol.getOptionalU64(req.args, "cookie", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "cookie must be u64");
        const requested_max = fs_protocol.getOptionalU32(req.args, "max", 128) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "max must be u32");
        const max_entries = @min(requested_max, 16384);

        const ctx = self.resolveNode(dir_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .namespace) {
            return self.opNamespaceReaddirPlus(ctx, cookie, max_entries);
        }
        if (export_cfg.source_kind == .gdrive) {
            return self.opGdriveReaddirPlus(ctx, cookie, max_entries);
        }
        const dir_stat = sourceStatAbsolute(export_cfg.source_kind, ctx.path) catch |err| return mapError(err);
        if (dir_stat.kind != .directory) return DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "node is not a directory");

        var dir = sourceOpenDirAbsolute(export_cfg.source_kind, ctx.path) catch |err| return mapError(err);
        defer dir.close();

        var payload = std.ArrayListUnmanaged(u8){};
        errdefer payload.deinit(self.allocator);
        payload.appendSlice(self.allocator, "{\"ents\":[") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        var emitted: u32 = 0;
        var count: u64 = 0;
        var first = true;
        var has_more = false;

        self.tryEmitDirSynthetic(ctx, ".", dir_id, dir_stat, cookie, max_entries, &payload, &emitted, &count, &first, &has_more) catch |err| {
            return mapError(err);
        };
        if (has_more) return self.finishReaddirPayload(&payload, cookie, emitted, false, dir_stat);

        self.tryEmitDotDot(ctx, cookie, max_entries, &payload, &emitted, &count, &first, &has_more) catch |err| {
            return mapError(err);
        };
        if (has_more) return self.finishReaddirPayload(&payload, cookie, emitted, false, dir_stat);

        var it = dir.iterate();
        while (it.next() catch |err| return mapError(err)) |entry| {
            if (!isValidChildName(entry.name)) continue;
            if (isHiddenLocalExportChild(export_cfg.source_kind, entry.name)) continue;
            if (count < cookie) {
                count += 1;
                continue;
            }
            if (emitted >= max_entries) {
                has_more = true;
                break;
            }

            const looked = sourceLookupChildAbsolute(
                export_cfg.source_kind,
                self.allocator,
                export_cfg.root_path,
                ctx.path,
                entry.name,
            ) catch |err| switch (err) {
                error.FileNotFound, error.NotDir, error.AccessDenied => continue,
                else => return mapError(err),
            };
            defer self.allocator.free(looked.resolved_path);

            const child_id = makeNodeId(ctx.export_index, looked.stat.inode);
            self.setNodePath(child_id, looked.resolved_path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            appendDirEntry(self.allocator, &payload, entry.name, child_id, looked.stat, &first, self.uid, self.gid) catch {
                return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            };
            emitted += 1;
            count += 1;
        }

        return self.finishReaddirPayload(&payload, cookie, emitted, !has_more, dir_stat);
    }

    fn opOpen(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "OPEN requires node");
        const flags = fs_protocol.getOptionalU32(req.args, "flags", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "flags must be u32");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .namespace) {
            return self.opNamespaceOpen(ctx, node_id, flags);
        }
        if (export_cfg.source_kind == .gdrive) {
            return self.opGdriveOpen(ctx, node_id, flags);
        }

        const access = accessModeFromFlags(flags);
        if (export_cfg.ro and access.wr) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const opened = sourceOpenAbsolute(export_cfg.source_kind, ctx.path, access.mode) catch |err| return mapError(err);
        errdefer opened.file.close();
        const file = opened.file;
        const stat = opened.stat;
        const generation = generationFromStat(stat);
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        self.handles.put(self.allocator, handle_id, .{
            .file = file,
            .export_index = ctx.export_index,
            .node_id = node_id,
            .caps = .{ .rd = access.rd, .wr = access.wr },
            .generation = generation,
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"h\":{d},\"caps\":{{\"rd\":{},\"wr\":{}}},\"gen\":{d}}}",
            .{ handle_id, access.rd, access.wr, generation },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opRead(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const handle_id = req.handle orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "READ requires h");
        const off = fs_protocol.getOptionalU64(req.args, "off", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "off must be u64");
        const len_requested = fs_protocol.getOptionalU32(req.args, "len", 65536) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "len must be u32");
        const len = @min(len_requested, max_read_bytes);

        if (self.namespace_handles.contains(handle_id)) {
            return self.opNamespaceRead(handle_id, off, len);
        }
        if (self.gdrive_handles.contains(handle_id) or self.gdrive_write_handles.contains(handle_id)) {
            return self.opGdriveRead(handle_id, off, len);
        }

        const handle = self.handles.getPtr(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (!handle.caps.rd) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not readable");

        const buf = self.allocator.alloc(u8, len) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(buf);
        const n = handle.file.pread(buf, off) catch |err| return mapError(err);
        const bytes = buf[0..n];

        const encoded = encodeBase64(self.allocator, bytes) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(encoded);

        const eof = n < len;
        const response = std.fmt.allocPrint(
            self.allocator,
            "{{\"data_b64\":\"{s}\",\"eof\":{}}}",
            .{ encoded, eof },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opClose(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const handle_id = req.handle orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "CLOSE requires h");
        if (self.namespace_handles.fetchRemove(handle_id) != null) {
            const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }
        if (self.gdrive_handles.contains(handle_id) or self.gdrive_write_handles.contains(handle_id)) return self.opGdriveClose(handle_id);
        const removed = self.handles.fetchRemove(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        removed.value.file.close();
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opLock(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const handle_id = req.handle orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "LOCK requires h");
        const kind = fs_protocol.getRequiredString(req.args, "kind") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "LOCK requires a.kind");
        const wait = fs_protocol.getOptionalBool(req.args, "wait", true) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "wait must be bool");

        if (self.namespace_handles.contains(handle_id)) {
            return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");
        }
        if (self.gdrive_handles.contains(handle_id) or self.gdrive_write_handles.contains(handle_id)) {
            return DispatchResult.failure(fs_protocol.Errno.ENOSYS, "source adapter operation not yet implemented");
        }

        const handle = self.handles.getPtr(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        const source_kind = self.exports.items[handle.export_index].source_kind;
        const mode: SourceLockMode = if (std.mem.eql(u8, kind, "shared"))
            .shared
        else if (std.mem.eql(u8, kind, "exclusive"))
            .exclusive
        else if (std.mem.eql(u8, kind, "unlock"))
            .unlock
        else
            return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid lock kind");
        sourceLockFile(source_kind, &handle.file, mode, wait) catch |err| return mapError(err);

        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opCreate(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "CREATE requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "CREATE requires a.name");
        const mode = fs_protocol.getOptionalU32(req.args, "mode", 0o100644) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "mode must be u32");
        const flags = fs_protocol.getOptionalU32(req.args, "flags", 2) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "flags must be u32");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceCreate(parent, name, mode, flags);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveCreate(parent, name, mode, flags);

        const path = std.fs.path.join(self.allocator, &.{ parent.path, name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(path);
        if (!isWithinRoot(export_cfg.root_path, path)) return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");

        var file = sourceCreateExclusiveAbsolute(export_cfg.source_kind, path, mode) catch |err| return mapError(err);
        errdefer file.close();

        const resolved_with_stat = sourceRealpathAndStatAbsolute(export_cfg.source_kind, self.allocator, path) catch |err| return mapError(err);
        defer self.allocator.free(resolved_with_stat.resolved_path);
        const stat = resolved_with_stat.stat;

        const node_id = makeNodeId(parent.export_index, stat.inode);
        self.setNodePath(node_id, resolved_with_stat.resolved_path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const access = accessModeFromFlags(flags);
        const handle_id = self.next_handle_id;
        self.next_handle_id += 1;
        self.handles.put(self.allocator, handle_id, .{
            .file = file,
            .export_index = parent.export_index,
            .node_id = node_id,
            .caps = .{ .rd = access.rd, .wr = true },
            .generation = generationFromStat(stat),
        }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        const attr_json = self.buildAttrJson(node_id, stat) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(attr_json);

        const response = std.fmt.allocPrint(self.allocator, "{{\"attr\":{s},\"h\":{d}}}", .{ attr_json, handle_id }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_id,
                .dir_gen = null,
            },
        });
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = generationFromStat(stat),
            },
        });
        return DispatchResult.success(response);
    }

    fn opWrite(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const handle_id = req.handle orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "WRITE requires h");
        const off = fs_protocol.getOptionalU64(req.args, "off", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "off must be u64");
        const data_b64 = fs_protocol.getRequiredString(req.args, "data_b64") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "WRITE requires a.data_b64");

        if (self.namespace_handles.contains(handle_id)) {
            return self.opNamespaceWrite(handle_id, off, data_b64);
        }
        if (self.gdrive_write_handles.getPtr(handle_id)) |handle| {
            if (!handle.caps.wr) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not writable");
            const decoded = decodeBase64(self.allocator, data_b64) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid base64 payload");
            defer self.allocator.free(decoded);
            if (decoded.len > max_write_bytes) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "WRITE exceeds max_write");

            const decoded_len_u64: u64 = decoded.len;
            const required_end = std.math.add(u64, off, decoded_len_u64) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "write too large");
            const previous_len = handle.staging_len;
            const growth = if (required_end > previous_len) required_end - previous_len else 0;
            if (growth > 0) self.reserveGdriveSpool(growth) catch |err| return mapError(err);
            if (off > handle.staging_len) {
                writeZeroFill(&handle.staging_file, handle.staging_len, off) catch {
                    if (growth > 0) self.releaseGdriveSpool(growth);
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "write staging failed");
                };
            }
            if (decoded.len > 0) {
                handle.staging_file.pwriteAll(decoded, off) catch {
                    if (growth > 0) self.releaseGdriveSpool(growth);
                    return DispatchResult.failure(fs_protocol.Errno.EIO, "write staging failed");
                };
            }
            if (required_end > handle.staging_len) {
                handle.staging_len = required_end;
            }
            handle.dirty = true;

            const response = std.fmt.allocPrint(self.allocator, "{{\"n\":{d}}}", .{decoded.len}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
            return DispatchResult.success(response);
        }

        if (self.gdrive_handles.contains(handle_id)) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const handle = self.handles.getPtr(handle_id) orelse return DispatchResult.failure(fs_protocol.Errno.EBADF, "unknown handle");
        if (!handle.caps.wr) return DispatchResult.failure(fs_protocol.Errno.EBADF, "handle not writable");
        if (self.exports.items[handle.export_index].ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");

        const decoded = decodeBase64(self.allocator, data_b64) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid base64 payload");
        defer self.allocator.free(decoded);
        if (decoded.len > max_write_bytes) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "WRITE exceeds max_write");

        handle.file.pwriteAll(decoded, off) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL = .{
                .node = handle.node_id,
                .what = .data,
                .gen = null,
            },
        });
        const response = std.fmt.allocPrint(self.allocator, "{{\"n\":{d}}}", .{decoded.len}) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opTruncate(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const node_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "TRUNCATE requires node");
        const size = fs_protocol.getOptionalU64(req.args, "sz", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "sz must be u64");
        const ctx = self.resolveNode(node_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[ctx.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceTruncate(ctx, size);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveTruncate(ctx, size);

        sourceTruncateAbsolute(export_cfg.source_kind, ctx.path, size) catch |err| return mapError(err);

        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opUnlink(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "UNLINK requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "UNLINK requires a.name");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceUnlink(parent, name);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveDeleteByName(parent, name, false);

        const path = std.fs.path.join(self.allocator, &.{ parent.path, name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(path);
        if (!isWithinRoot(export_cfg.root_path, path)) return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");

        sourceDeleteFileAbsolute(export_cfg.source_kind, path) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opMkdir(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "MKDIR requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "MKDIR requires a.name");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceMkdir(parent, name);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveMkdir(parent, name);

        const path = std.fs.path.join(self.allocator, &.{ parent.path, name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(path);
        if (!isWithinRoot(export_cfg.root_path, path)) return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");

        sourceMakeDirAbsolute(export_cfg.source_kind, path) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opRmdir(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const parent_id = req.node orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "RMDIR requires node");
        const name = fs_protocol.getRequiredString(req.args, "name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "RMDIR requires a.name");
        if (!isValidChildName(name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid child name");

        const parent = self.resolveNode(parent_id) catch |err| return mapError(err);
        const export_cfg = self.exports.items[parent.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceRmdir(parent, name);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveDeleteByName(parent, name, true);

        const path = std.fs.path.join(self.allocator, &.{ parent.path, name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(path);
        if (!isWithinRoot(export_cfg.root_path, path)) return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");

        sourceDeleteDirAbsolute(export_cfg.source_kind, path) catch |err| return mapError(err);
        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = parent_id,
                .dir_gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn opRename(self: *NodeOps, req: fs_protocol.ParsedRequest) DispatchResult {
        const old_parent_id = fs_protocol.getOptionalU64(req.args, "old_parent", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "old_parent must be u64");
        const old_name = fs_protocol.getRequiredString(req.args, "old_name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "RENAME requires a.old_name");
        const new_parent_id = fs_protocol.getOptionalU64(req.args, "new_parent", 0) catch return DispatchResult.failure(fs_protocol.Errno.EINVAL, "new_parent must be u64");
        const new_name = fs_protocol.getRequiredString(req.args, "new_name") orelse return DispatchResult.failure(fs_protocol.Errno.EINVAL, "RENAME requires a.new_name");
        if (!isValidChildName(old_name) or !isValidChildName(new_name)) return DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid rename child name");

        const old_parent = self.resolveNode(old_parent_id) catch |err| return mapError(err);
        const new_parent = self.resolveNode(new_parent_id) catch |err| return mapError(err);
        if (old_parent.export_index != new_parent.export_index) return DispatchResult.failure(fs_protocol.Errno.EXDEV, "cross-export rename is not supported");

        const export_cfg = self.exports.items[old_parent.export_index];
        if (export_cfg.source_kind == .namespace) return self.opNamespaceRename(old_parent, new_parent, old_name, new_name);
        if (export_cfg.ro) return DispatchResult.failure(fs_protocol.Errno.EROFS, "export is read-only");
        if (export_cfg.source_kind == .gdrive) return self.opGdriveRename(old_parent, new_parent, old_name, new_name);

        const old_path = std.fs.path.join(self.allocator, &.{ old_parent.path, old_name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(old_path);
        const new_path = std.fs.path.join(self.allocator, &.{ new_parent.path, new_name }) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        defer self.allocator.free(new_path);

        if (!isWithinRoot(export_cfg.root_path, old_path) or !isWithinRoot(export_cfg.root_path, new_path)) {
            return DispatchResult.failure(fs_protocol.Errno.EACCES, "path outside export root");
        }

        const old_resolved_with_stat = sourceRealpathAndStatAbsolute(export_cfg.source_kind, self.allocator, old_path) catch |err| return mapError(err);
        defer self.allocator.free(old_resolved_with_stat.resolved_path);
        const old_stat = old_resolved_with_stat.stat;
        const node_id = makeNodeId(old_parent.export_index, old_stat.inode);

        sourceRenameAbsolute(export_cfg.source_kind, old_path, new_path) catch |err| return mapError(err);

        const new_resolved_with_stat = sourceRealpathAndStatAbsolute(export_cfg.source_kind, self.allocator, new_path) catch |err| return mapError(err);
        defer self.allocator.free(new_resolved_with_stat.resolved_path);
        self.setNodePath(node_id, new_resolved_with_stat.resolved_path) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");

        self.queueInvalidation(.{
            .INVAL_DIR = .{
                .dir = old_parent_id,
                .dir_gen = null,
            },
        });
        if (old_parent_id != new_parent_id) {
            self.queueInvalidation(.{
                .INVAL_DIR = .{
                    .dir = new_parent_id,
                    .dir_gen = null,
                },
            });
        }
        self.queueInvalidation(.{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = null,
            },
        });
        const response = self.allocator.dupe(u8, "{}") catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(response);
    }

    fn resolveNode(self: *NodeOps, node_id: u64) !NodeContext {
        const export_tag = (node_id & node_id_export_mask) >> node_id_export_shift;
        if (export_tag == 0) return error.FileNotFound;
        const export_index = export_tag - 1;
        if (export_index >= self.exports.items.len) return error.FileNotFound;
        const path = self.node_paths.get(node_id) orelse return error.FileNotFound;

        return .{
            .node_id = node_id,
            .export_index = @intCast(export_index),
            .path = path,
        };
    }

    fn setNodePath(self: *NodeOps, node_id: u64, path: []const u8) !void {
        if (self.node_paths.get(node_id)) |existing| {
            if (std.mem.eql(u8, existing, path)) return;
        }

        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);

        if (try self.node_paths.fetchPut(self.allocator, node_id, owned)) |existing| {
            self.allocator.free(existing.value);
        }
    }

    fn buildAttrJson(self: *NodeOps, node_id: u64, stat: std.fs.File.Stat) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"id\":{d},\"k\":{d},\"m\":{d},\"n\":{d},\"u\":{d},\"g\":{d},\"sz\":{d},\"at\":{d},\"mt\":{d},\"ct\":{d},\"gen\":{d}}}",
            .{
                node_id,
                kindCode(stat.kind),
                @as(u32, @intCast(@min(stat.mode, std.math.maxInt(u32)))),
                if (stat.kind == .directory) @as(u32, 2) else @as(u32, 1),
                self.uid,
                self.gid,
                stat.size,
                clampI128ToI64(stat.atime),
                clampI128ToI64(stat.mtime),
                clampI128ToI64(stat.ctime),
                generationFromStat(stat),
            },
        );
    }

    fn tryEmitDirSynthetic(
        self: *NodeOps,
        ctx: NodeContext,
        name: []const u8,
        node_id: u64,
        stat: std.fs.File.Stat,
        cookie: u64,
        max_entries: u32,
        payload: *std.ArrayListUnmanaged(u8),
        emitted: *u32,
        count: *u64,
        first: *bool,
        has_more: *bool,
    ) !void {
        _ = ctx;
        if (count.* < cookie) {
            count.* += 1;
            return;
        }
        if (emitted.* >= max_entries) {
            has_more.* = true;
            return;
        }

        try appendDirEntry(self.allocator, payload, name, node_id, stat, first, self.uid, self.gid);
        emitted.* += 1;
        count.* += 1;
    }

    fn tryEmitDotDot(
        self: *NodeOps,
        ctx: NodeContext,
        cookie: u64,
        max_entries: u32,
        payload: *std.ArrayListUnmanaged(u8),
        emitted: *u32,
        count: *u64,
        first: *bool,
        has_more: *bool,
    ) !void {
        if (count.* < cookie) {
            count.* += 1;
            return;
        }
        if (emitted.* >= max_entries) {
            has_more.* = true;
            return;
        }

        const export_cfg = self.exports.items[ctx.export_index];
        const export_root = export_cfg.root_path;
        const maybe_parent = std.fs.path.dirname(ctx.path) orelse ctx.path;
        const parent_path = if (isWithinRoot(export_root, maybe_parent)) maybe_parent else export_root;
        const parent_stat = sourceStatAbsolute(export_cfg.source_kind, parent_path) catch |err| return err;
        const parent_id = makeNodeId(ctx.export_index, parent_stat.inode);
        try self.setNodePath(parent_id, parent_path);
        try appendDirEntry(self.allocator, payload, "..", parent_id, parent_stat, first, self.uid, self.gid);
        emitted.* += 1;
        count.* += 1;
    }

    fn finishReaddirPayload(
        self: *NodeOps,
        payload: *std.ArrayListUnmanaged(u8),
        cookie: u64,
        emitted: u32,
        eof: bool,
        dir_stat: std.fs.File.Stat,
    ) DispatchResult {
        payload.writer(self.allocator).print(
            "],\"next\":{d},\"eof\":{},\"dir_gen\":{d}}}",
            .{ cookie + emitted, eof, generationFromStat(dir_stat) },
        ) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory");
        return DispatchResult.success(payload.toOwnedSlice(self.allocator) catch return DispatchResult.failure(fs_protocol.Errno.EIO, "out of memory"));
    }

    fn pollFilesystemInvalidationsLocked(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        max_events: usize,
    ) ![]fs_protocol.InvalidationEvent {
        var current = std.AutoHashMapUnmanaged(u64, WatchedNode){};
        errdefer current.deinit(self.allocator);
        try self.collectWatchSnapshot(&current);

        if (!self.watch_initialized) {
            self.watch_snapshot.deinit(self.allocator);
            self.watch_snapshot = current;
            self.watch_initialized = true;
            const empty = try allocator.alloc(fs_protocol.InvalidationEvent, 0);
            return self.appendGdriveInvalidations(allocator, empty, max_events);
        }

        var invalid_dirs = std.AutoHashMapUnmanaged(u64, void){};
        defer invalid_dirs.deinit(self.allocator);
        var invalid_nodes = std.AutoHashMapUnmanaged(u64, void){};
        defer invalid_nodes.deinit(self.allocator);

        var current_it = current.iterator();
        while (current_it.next()) |entry| {
            const node_id = entry.key_ptr.*;
            const state = entry.value_ptr.*;
            if (self.watch_snapshot.get(node_id)) |prev| {
                if (prev.parent_id != state.parent_id) {
                    if (prev.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
                    if (state.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
                    try invalid_nodes.put(self.allocator, node_id, {});
                }
                if (prev.kind != state.kind) {
                    if (prev.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
                    if (state.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
                    try invalid_nodes.put(self.allocator, node_id, {});
                }
                if (prev.mtime != state.mtime or prev.size != state.size) {
                    switch (state.kind) {
                        .directory => {
                            try invalid_dirs.put(self.allocator, node_id, {});
                            try invalid_nodes.put(self.allocator, node_id, {});
                        },
                        else => try invalid_nodes.put(self.allocator, node_id, {}),
                    }
                }
            } else {
                if (state.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
                try invalid_nodes.put(self.allocator, node_id, {});
            }
        }

        var old_it = self.watch_snapshot.iterator();
        while (old_it.next()) |entry| {
            const node_id = entry.key_ptr.*;
            const state = entry.value_ptr.*;
            if (current.contains(node_id)) continue;

            if (state.parent_id) |dir_id| try invalid_dirs.put(self.allocator, dir_id, {});
            try invalid_nodes.put(self.allocator, node_id, {});

            if (self.node_paths.fetchRemove(node_id)) |removed| {
                self.allocator.free(removed.value);
            }
        }

        var old_snapshot = self.watch_snapshot;
        self.watch_snapshot = current;
        old_snapshot.deinit(self.allocator);

        const total_changed = invalid_dirs.count() + invalid_nodes.count();
        if (total_changed == 0 or max_events == 0) {
            const empty = try allocator.alloc(fs_protocol.InvalidationEvent, 0);
            return self.appendGdriveInvalidations(allocator, empty, max_events);
        }

        var out = std.ArrayListUnmanaged(fs_protocol.InvalidationEvent){};
        errdefer out.deinit(allocator);

        if (total_changed > max_events) {
            for (self.exports.items) |export_cfg| {
                if (out.items.len >= max_events) break;
                try out.append(allocator, .{
                    .INVAL_DIR = .{
                        .dir = export_cfg.root_node_id,
                        .dir_gen = null,
                    },
                });
            }
            const base = try out.toOwnedSlice(allocator);
            return self.appendGdriveInvalidations(allocator, base, max_events);
        }

        var dir_it = invalid_dirs.iterator();
        while (dir_it.next()) |entry| {
            try out.append(allocator, .{
                .INVAL_DIR = .{
                    .dir = entry.key_ptr.*,
                    .dir_gen = null,
                },
            });
        }

        var node_it = invalid_nodes.iterator();
        while (node_it.next()) |entry| {
            try out.append(allocator, .{
                .INVAL = .{
                    .node = entry.key_ptr.*,
                    .what = .all,
                    .gen = null,
                },
            });
        }

        const base = try out.toOwnedSlice(allocator);
        return self.appendGdriveInvalidations(allocator, base, max_events);
    }

    fn appendGdriveInvalidations(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        base: []fs_protocol.InvalidationEvent,
        max_events: usize,
    ) ![]fs_protocol.InvalidationEvent {
        if (max_events == 0 or base.len >= max_events) return base;
        const remaining = max_events - base.len;
        const cloud = try self.pollGdriveInvalidations(allocator, remaining);
        if (cloud.len == 0) {
            allocator.free(cloud);
            return base;
        }

        const merged = try allocator.alloc(fs_protocol.InvalidationEvent, base.len + cloud.len);
        @memcpy(merged[0..base.len], base);
        @memcpy(merged[base.len..], cloud);
        allocator.free(base);
        allocator.free(cloud);
        return merged;
    }

    fn pollGdriveInvalidations(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        max_events: usize,
    ) ![]fs_protocol.InvalidationEvent {
        if (max_events == 0 or !self.gdrive_backend_enabled) return allocator.alloc(fs_protocol.InvalidationEvent, 0);

        var out = std.ArrayListUnmanaged(fs_protocol.InvalidationEvent){};
        errdefer out.deinit(allocator);

        var seen_dirs = std.AutoHashMapUnmanaged(u64, void){};
        defer seen_dirs.deinit(self.allocator);
        var seen_nodes = std.AutoHashMapUnmanaged(u64, void){};
        defer seen_nodes.deinit(self.allocator);

        for (self.exports.items, 0..) |export_cfg, export_index| {
            if (out.items.len >= max_events) break;
            if (export_cfg.source_kind != .gdrive) continue;

            const token = self.gdriveTokenForExport(export_index) catch continue;
            if (token == null) continue;
            const access_token = token.?;

            const now_ms = gdriveNowMs();
            const state = self.gdrive_changes.getPtr(export_index) orelse blk: {
                try self.gdrive_changes.put(self.allocator, export_index, .{});
                break :blk self.gdrive_changes.getPtr(export_index).?;
            };
            self.ensureGdriveChangeStateLoaded(export_index, state);

            if (state.backoff_until_ms > now_ms) continue;
            if (state.last_poll_ms != 0 and now_ms - state.last_poll_ms < gdrive_poll_interval_ms) continue;

            if (state.page_token == null) {
                const start_token = fs_gdrive_backend.getStartPageToken(self.allocator, access_token) catch |err| {
                    switch (err) {
                        error.GdriveRateLimited, error.GdriveUnexpectedStatus => state.backoff_until_ms = now_ms + gdrive_backoff_ms,
                        else => {},
                    }
                    continue;
                };
                if (state.page_token) |old| self.allocator.free(old);
                state.page_token = start_token;
                self.persistGdriveChangeState(export_index, state);
                state.last_poll_ms = now_ms;
                continue;
            }

            var page = fs_gdrive_backend.listChanges(self.allocator, access_token, state.page_token.?) catch |err| {
                switch (err) {
                    error.GdriveRateLimited => state.backoff_until_ms = now_ms + gdrive_backoff_ms,
                    error.GdriveUnexpectedStatus => {
                        state.backoff_until_ms = now_ms + gdrive_backoff_ms;
                        if (state.page_token) |old| self.allocator.free(old);
                        state.page_token = null;
                        self.clearPersistedGdriveChangeState(state);
                    },
                    else => {},
                }
                continue;
            };
            defer page.deinit(self.allocator);

            for (page.changes) |change| {
                if (out.items.len >= max_events) break;
                try self.applyGdriveChange(
                    allocator,
                    export_index,
                    change,
                    &seen_dirs,
                    &seen_nodes,
                    &out,
                    max_events,
                );
            }

            try self.updateGdriveChangeToken(export_index, state, page);
            state.last_poll_ms = now_ms;
            state.backoff_until_ms = 0;
        }

        return out.toOwnedSlice(allocator);
    }

    fn applyGdriveChange(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        export_index: usize,
        change: fs_gdrive_backend.Change,
        seen_dirs: *std.AutoHashMapUnmanaged(u64, void),
        seen_nodes: *std.AutoHashMapUnmanaged(u64, void),
        out: *std.ArrayListUnmanaged(fs_protocol.InvalidationEvent),
        max_events: usize,
    ) !void {
        const root_id = self.exports.items[export_index].root_node_id;
        var matches = std.ArrayListUnmanaged(struct {
            node_id: u64,
            parent_node_id: ?u64,
            parent_file_id: ?[]const u8,
        }){};
        defer matches.deinit(allocator);

        var it = self.gdrive_nodes.iterator();
        while (it.next()) |entry| {
            const node = entry.value_ptr.*;
            if (node.export_index != export_index) continue;
            if (!std.mem.eql(u8, node.file_id, change.file_id)) continue;
            try matches.append(allocator, .{
                .node_id = entry.key_ptr.*,
                .parent_node_id = node.parent_node_id,
                .parent_file_id = node.parent_file_id,
            });
        }

        if (matches.items.len == 0) {
            if (change.file) |file| {
                if (file.primary_parent_id) |parent_file_id| {
                    if (self.gdriveFirstNodeIdForFileId(export_index, parent_file_id)) |parent_node_id| {
                        try self.queueUniqueDirInvalidation(allocator, parent_node_id, seen_dirs, out, max_events);
                        return;
                    }
                }
            }
            try self.queueUniqueDirInvalidation(allocator, root_id, seen_dirs, out, max_events);
            return;
        }

        for (matches.items) |matched| {
            if (out.items.len >= max_events) return;
            try self.queueUniqueNodeInvalidation(allocator, matched.node_id, seen_nodes, out, max_events);
            const old_parent_id = matched.parent_node_id orelse root_id;
            try self.queueUniqueDirInvalidation(allocator, old_parent_id, seen_dirs, out, max_events);

            if (change.removed) {
                if (self.gdrive_nodes.fetchRemove(matched.node_id)) |removed| {
                    var removed_node = removed.value;
                    removed_node.deinit(self.allocator);
                }
                if (self.node_paths.fetchRemove(matched.node_id)) |removed_path| {
                    self.allocator.free(removed_path.value);
                }
                continue;
            }

            if (change.file) |file| {
                const new_parent_file_id = file.primary_parent_id orelse matched.parent_file_id;
                const new_parent_node_id = if (new_parent_file_id) |parent_file_id|
                    self.gdriveFirstNodeIdForFileId(export_index, parent_file_id) orelse matched.parent_node_id
                else
                    matched.parent_node_id;
                const resolved_parent_id = new_parent_node_id orelse root_id;
                self.registerGdriveNode(export_index, matched.node_id, new_parent_node_id, new_parent_file_id, file) catch {};
                if (resolved_parent_id != old_parent_id) {
                    try self.queueUniqueDirInvalidation(allocator, resolved_parent_id, seen_dirs, out, max_events);
                }
            }
        }
    }

    fn updateGdriveChangeToken(
        self: *NodeOps,
        export_index: usize,
        state: *GdriveChangeState,
        page: fs_gdrive_backend.ChangesPage,
    ) !void {
        const replacement = page.next_page_token orelse page.new_start_page_token orelse return;
        const owned = try self.allocator.dupe(u8, replacement);
        if (state.page_token) |old| self.allocator.free(old);
        state.page_token = owned;
        self.persistGdriveChangeState(export_index, state);
    }

    fn queueUniqueDirInvalidation(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        dir_id: u64,
        seen: *std.AutoHashMapUnmanaged(u64, void),
        out: *std.ArrayListUnmanaged(fs_protocol.InvalidationEvent),
        max_events: usize,
    ) !void {
        if (out.items.len >= max_events) return;
        if (seen.contains(dir_id)) return;
        try seen.put(self.allocator, dir_id, {});
        try out.append(allocator, .{
            .INVAL_DIR = .{
                .dir = dir_id,
                .dir_gen = null,
            },
        });
    }

    fn queueUniqueNodeInvalidation(
        self: *NodeOps,
        allocator: std.mem.Allocator,
        node_id: u64,
        seen: *std.AutoHashMapUnmanaged(u64, void),
        out: *std.ArrayListUnmanaged(fs_protocol.InvalidationEvent),
        max_events: usize,
    ) !void {
        if (out.items.len >= max_events) return;
        if (seen.contains(node_id)) return;
        try seen.put(self.allocator, node_id, {});
        try out.append(allocator, .{
            .INVAL = .{
                .node = node_id,
                .what = .all,
                .gen = null,
            },
        });
    }

    fn collectWatchSnapshot(self: *NodeOps, out: *std.AutoHashMapUnmanaged(u64, WatchedNode)) !void {
        for (self.exports.items, 0..) |export_cfg, export_index| {
            if (export_cfg.source_kind == .gdrive or export_cfg.source_kind == .namespace) continue;
            const root_stat = std.fs.cwd().statFile(export_cfg.root_path) catch |err| {
                if (err == error.FileNotFound or err == error.AccessDenied) continue;
                return err;
            };

            try self.collectWatchSubtree(
                out,
                export_index,
                null,
                export_cfg.root_path,
                export_cfg.root_node_id,
                root_stat,
                true,
            );
        }
    }

    fn collectWatchSubtree(
        self: *NodeOps,
        out: *std.AutoHashMapUnmanaged(u64, WatchedNode),
        export_index: usize,
        parent_id: ?u64,
        path: []const u8,
        node_id: u64,
        stat: std.fs.File.Stat,
        recurse: bool,
    ) !void {
        try out.put(self.allocator, node_id, .{
            .parent_id = parent_id,
            .kind = watchKindFromStatKind(stat.kind),
            .mtime = stat.mtime,
            .size = stat.size,
        });
        self.setNodePath(node_id, path) catch {};

        if (!recurse or stat.kind != .directory) return;

        var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) return;
            return err;
        };
        defer dir.close();

        var it = dir.iterate();
        while (true) {
            const maybe_entry = it.next() catch |err| {
                if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) break;
                return err;
            };
            const entry = maybe_entry orelse break;
            if (!isValidChildName(entry.name)) continue;

            const child_path = std.fs.path.join(self.allocator, &.{ path, entry.name }) catch return error.OutOfMemory;
            defer self.allocator.free(child_path);

            const child_stat = std.fs.cwd().statFile(child_path) catch |err| {
                if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
                return err;
            };

            const child_id = makeNodeId(export_index, child_stat.inode);
            const should_recurse = child_stat.kind == .directory and entry.kind != .sym_link;
            if (should_recurse) {
                const export_root = self.exports.items[export_index].root_path;
                const child_resolved = std.fs.cwd().realpathAlloc(self.allocator, child_path) catch |err| {
                    if (err == error.FileNotFound or err == error.NotDir or err == error.AccessDenied) continue;
                    return err;
                };
                defer self.allocator.free(child_resolved);
                if (!isWithinRoot(export_root, child_resolved)) continue;

                try self.collectWatchSubtree(
                    out,
                    export_index,
                    node_id,
                    child_resolved,
                    child_id,
                    child_stat,
                    true,
                );
                continue;
            }

            try self.collectWatchSubtree(
                out,
                export_index,
                node_id,
                child_path,
                child_id,
                child_stat,
                false,
            );
        }
    }

    fn queueInvalidation(self: *NodeOps, event: fs_protocol.InvalidationEvent) void {
        self.pending_events.append(self.allocator, event) catch {};
    }
};

fn defaultGdriveCredentialHandle(allocator: std.mem.Allocator, export_name: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "gdrive.");
    for (export_name) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.') {
            try out.append(allocator, ch);
        } else {
            try out.append(allocator, '-');
        }
    }
    if (out.items.len == "gdrive.".len) try out.appendSlice(allocator, "default");
    return out.toOwnedSlice(allocator);
}

fn buildGdriveChangePersistHandle(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "gdrive.changes.");
    for (raw) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.') {
            try out.append(allocator, ch);
        } else {
            try out.append(allocator, '-');
        }
    }
    if (out.items.len == "gdrive.changes.".len) try out.appendSlice(allocator, "default");
    return out.toOwnedSlice(allocator);
}

const GdriveChangeStateBundle = struct {
    page_token: []u8,
    updated_at_ms: u64,
    source_id: ?[]u8,

    fn deinit(self: *GdriveChangeStateBundle, allocator: std.mem.Allocator) void {
        allocator.free(self.page_token);
        if (self.source_id) |value| allocator.free(value);
        self.* = undefined;
    }
};

fn parseGdriveChangeStateBundle(allocator: std.mem.Allocator, secret: []const u8) !GdriveChangeStateBundle {
    const trimmed = std.mem.trim(u8, secret, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '{') return error.InvalidFormat;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidFormat;
    const obj = parsed.value.object;

    const token_v = obj.get("page_token") orelse return error.InvalidFormat;
    if (token_v != .string) return error.InvalidFormat;
    const page_token = try allocator.dupe(u8, token_v.string);
    errdefer allocator.free(page_token);

    const updated_at_ms: u64 = if (obj.get("updated_at_ms")) |updated_v|
        switch (updated_v) {
            .integer => |num| if (num <= 0) 0 else @intCast(num),
            .string => |text| std.fmt.parseInt(u64, text, 10) catch 0,
            else => 0,
        }
    else
        0;

    const source_id = if (obj.get("source_id")) |source_v|
        if (source_v == .string and source_v.string.len > 0)
            try allocator.dupe(u8, source_v.string)
        else
            null
    else
        null;
    errdefer if (source_id) |value| allocator.free(value);

    return .{
        .page_token = page_token,
        .updated_at_ms = updated_at_ms,
        .source_id = source_id,
    };
}

fn serializeGdriveChangeStateBundle(
    allocator: std.mem.Allocator,
    source_id: []const u8,
    page_token: []const u8,
    updated_at_ms: u64,
) ![]u8 {
    const escaped_source_id = try fs_protocol.jsonEscape(allocator, source_id);
    defer allocator.free(escaped_source_id);
    const escaped_page_token = try fs_protocol.jsonEscape(allocator, page_token);
    defer allocator.free(escaped_page_token);
    return std.fmt.allocPrint(
        allocator,
        "{{\"kind\":\"gdrive_changes_v1\",\"source_id\":\"{s}\",\"page_token\":\"{s}\",\"updated_at_ms\":{d}}}",
        .{ escaped_source_id, escaped_page_token, updated_at_ms },
    );
}

fn parseGdriveOauthState(allocator: std.mem.Allocator, secret: []const u8) !GdriveOauthState {
    const trimmed = std.mem.trim(u8, secret, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '{') return error.InvalidFormat;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidFormat;
    const obj = parsed.value.object;

    const client_id_v = obj.get("client_id") orelse return error.InvalidFormat;
    const client_secret_v = obj.get("client_secret") orelse return error.InvalidFormat;
    const refresh_token_v = obj.get("refresh_token") orelse return error.InvalidFormat;
    if (client_id_v != .string or client_secret_v != .string or refresh_token_v != .string) return error.InvalidFormat;

    const access_token = if (obj.get("access_token")) |token_v|
        if (token_v == .string and token_v.string.len > 0)
            try allocator.dupe(u8, token_v.string)
        else
            null
    else
        null;
    errdefer if (access_token) |token| allocator.free(token);

    const expires_at_ms: u64 = if (obj.get("expires_at_ms")) |expires_v|
        switch (expires_v) {
            .integer => |num| if (num <= 0) 0 else @intCast(num),
            .string => |text| std.fmt.parseInt(u64, text, 10) catch 0,
            else => 0,
        }
    else
        0;

    const client_id = try allocator.dupe(u8, client_id_v.string);
    errdefer allocator.free(client_id);
    const client_secret = try allocator.dupe(u8, client_secret_v.string);
    errdefer allocator.free(client_secret);
    const refresh_token = try allocator.dupe(u8, refresh_token_v.string);
    errdefer allocator.free(refresh_token);

    return .{
        .client_id = client_id,
        .client_secret = client_secret,
        .refresh_token = refresh_token,
        .access_token = access_token,
        .expires_at_ms = expires_at_ms,
    };
}

fn serializeGdriveOauthState(allocator: std.mem.Allocator, oauth: GdriveOauthState) ![]u8 {
    const escaped_client_id = try fs_protocol.jsonEscape(allocator, oauth.client_id);
    defer allocator.free(escaped_client_id);
    const escaped_client_secret = try fs_protocol.jsonEscape(allocator, oauth.client_secret);
    defer allocator.free(escaped_client_secret);
    const escaped_refresh = try fs_protocol.jsonEscape(allocator, oauth.refresh_token);
    defer allocator.free(escaped_refresh);
    const access_token_json = if (oauth.access_token) |token| blk: {
        const escaped = try fs_protocol.jsonEscape(allocator, token);
        defer allocator.free(escaped);
        break :blk try std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    } else try allocator.dupe(u8, "null");
    defer allocator.free(access_token_json);

    return std.fmt.allocPrint(
        allocator,
        "{{\"kind\":\"google_oauth\",\"client_id\":\"{s}\",\"client_secret\":\"{s}\",\"refresh_token\":\"{s}\",\"access_token\":{s},\"expires_at_ms\":{d}}}",
        .{ escaped_client_id, escaped_client_secret, escaped_refresh, access_token_json, oauth.expires_at_ms },
    );
}

fn gdriveNowMs() u64 {
    const now = std.time.milliTimestamp();
    if (now <= 0) return 0;
    return @intCast(now);
}

fn accessModeFromFlags(flags: u32) struct {
    mode: std.fs.File.OpenMode,
    rd: bool,
    wr: bool,
} {
    const access = flags & 0x3;
    return switch (access) {
        1 => .{ .mode = .write_only, .rd = false, .wr = true },
        2 => .{ .mode = .read_write, .rd = true, .wr = true },
        else => .{ .mode = .read_only, .rd = true, .wr = false },
    };
}

fn isValidChildName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    if (std.mem.indexOfScalar(u8, name, '/')) |_| return false;
    if (std.mem.indexOfScalar(u8, name, '\\')) |_| return false;
    if (std.mem.indexOfScalar(u8, name, 0)) |_| return false;
    return true;
}

fn isHiddenLocalExportChild(source_kind: fs_source_adapter.SourceKind, name: []const u8) bool {
    return switch (source_kind) {
        .namespace, .gdrive => false,
        else => std.mem.eql(u8, name, ".spiderweb-sandbox"),
    };
}

fn namespaceJoinPath(allocator: std.mem.Allocator, parent_path: []const u8, name: []const u8) ![]u8 {
    if (std.mem.eql(u8, parent_path, "/")) {
        return std.fmt.allocPrint(allocator, "/{s}", .{name});
    }
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent_path, name });
}

fn isWithinRoot(root: []const u8, target: []const u8) bool {
    var normalized_root = root;
    while (normalized_root.len > 1 and normalized_root[normalized_root.len - 1] == std.fs.path.sep) {
        normalized_root = normalized_root[0 .. normalized_root.len - 1];
    }

    if (normalized_root.len == 1 and normalized_root[0] == std.fs.path.sep) {
        return target.len > 0 and target[0] == std.fs.path.sep;
    }

    if (std.mem.eql(u8, normalized_root, target)) return true;
    if (!std.mem.startsWith(u8, target, normalized_root)) return false;
    if (target.len <= normalized_root.len) return false;
    return target[normalized_root.len] == std.fs.path.sep;
}

test "fs_node_ops: isWithinRoot handles root and exact-prefix boundaries" {
    try std.testing.expect(isWithinRoot("/", "/"));
    try std.testing.expect(isWithinRoot("/", "/var"));
    try std.testing.expect(isWithinRoot("/safe", "/safe"));
    try std.testing.expect(isWithinRoot("/safe", "/safe/work"));
    try std.testing.expect(!isWithinRoot("/safe", "/safeguard"));
}

fn kindCode(kind: std.fs.File.Kind) u8 {
    return switch (kind) {
        .file => 1,
        .directory => 2,
        .sym_link => 3,
        else => 1,
    };
}

fn watchKindFromStatKind(kind: std.fs.File.Kind) WatchNodeKind {
    return switch (kind) {
        .directory => .directory,
        .sym_link => .symlink,
        else => .file,
    };
}

fn generationFromStat(stat: std.fs.File.Stat) u64 {
    if (stat.mtime <= 0) return 0;
    return @intCast(@min(stat.mtime, std.math.maxInt(u64)));
}

fn clampI128ToI64(value: i128) i64 {
    if (value > std.math.maxInt(i64)) return std.math.maxInt(i64);
    if (value < std.math.minInt(i64)) return std.math.minInt(i64);
    return @intCast(value);
}

fn makeNodeId(export_index: usize, inode: anytype) u64 {
    return ((@as(u64, @intCast(export_index + 1))) << node_id_export_shift) | (inodeToU64(inode) & node_id_inode_mask);
}

fn inodeToU64(inode: anytype) u64 {
    const InodeType = @TypeOf(inode);
    if (comptime @typeInfo(InodeType).int.signedness == .signed) {
        if (inode < 0) return 0;
    }
    return @intCast(inode);
}

fn appendDirEntry(
    allocator: std.mem.Allocator,
    payload: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    node_id: u64,
    stat: std.fs.File.Stat,
    first: *bool,
    uid: u32,
    gid: u32,
) !void {
    if (!first.*) try payload.append(allocator, ',');
    first.* = false;

    const escaped_name = try fs_protocol.jsonEscape(allocator, name);
    defer allocator.free(escaped_name);

    try payload.writer(allocator).print("{{\"name\":\"{s}\",\"attr\":", .{escaped_name});
    const attr_json = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":{d},\"k\":{d},\"m\":{d},\"n\":{d},\"u\":{d},\"g\":{d},\"sz\":{d},\"at\":{d},\"mt\":{d},\"ct\":{d},\"gen\":{d}}}",
        .{
            node_id,
            kindCode(stat.kind),
            @as(u32, @intCast(@min(stat.mode, std.math.maxInt(u32)))),
            if (stat.kind == .directory) @as(u32, 2) else @as(u32, 1),
            uid,
            gid,
            stat.size,
            clampI128ToI64(stat.atime),
            clampI128ToI64(stat.mtime),
            clampI128ToI64(stat.ctime),
            generationFromStat(stat),
        },
    );
    defer allocator.free(attr_json);
    try payload.appendSlice(allocator, attr_json);
    try payload.append(allocator, '}');
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

fn resolveGdriveSpoolDirForExports(allocator: std.mem.Allocator, exports: []const ExportConfig) ![]u8 {
    if (!builtin.is_test) return resolveGdriveSpoolDir(allocator);

    if (std.process.getEnvVarOwned(allocator, gdrive_spool_dir_env_var)) |raw| {
        allocator.free(raw);
        return resolveGdriveSpoolDir(allocator);
    } else |_| {}

    for (exports) |export_cfg| {
        if (export_cfg.source_kind == .gdrive) continue;
        if (!std.fs.path.isAbsolute(export_cfg.root_path)) continue;

        const path = try std.fs.path.join(allocator, &.{ export_cfg.root_path, ".spiderweb-gdrive-spool" });
        errdefer allocator.free(path);
        std.fs.makeDirAbsolute(path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        return path;
    }

    return resolveGdriveSpoolDir(allocator);
}

fn hasGdriveExports(exports: []const ExportConfig) bool {
    for (exports) |export_cfg| {
        if (export_cfg.source_kind == .gdrive) return true;
    }
    return false;
}

fn resolveGdriveSpoolDir(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, gdrive_spool_dir_env_var)) |raw| {
        defer allocator.free(raw);
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        const chosen = if (trimmed.len == 0) gdrive_spool_default_dir else trimmed;
        const out = try makeAbsolutePath(allocator, chosen);
        errdefer allocator.free(out);
        std.fs.makeDirAbsolute(out) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        return out;
    } else |_| {}

    if (std.process.getEnvVarOwned(allocator, "TMPDIR")) |tmp_raw| {
        defer allocator.free(tmp_raw);
        const trimmed = std.mem.trim(u8, tmp_raw, " \t\r\n");
        if (trimmed.len > 0) {
            const joined = try std.fmt.allocPrint(allocator, "{s}/spiderweb-gdrive-spool", .{trimmed});
            defer allocator.free(joined);
            const path = try makeAbsolutePath(allocator, joined);
            errdefer allocator.free(path);
            std.fs.makeDirAbsolute(path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            return path;
        }
    } else |_| {}

    const fallback = try allocator.dupe(u8, gdrive_spool_default_dir);
    errdefer allocator.free(fallback);
    std.fs.makeDirAbsolute(fallback) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    return fallback;
}

fn resolveGdriveSpoolLimit(allocator: std.mem.Allocator) u64 {
    const raw = std.process.getEnvVarOwned(allocator, gdrive_spool_limit_env_var) catch return gdrive_spool_default_limit_bytes;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return gdrive_spool_default_limit_bytes;
    return std.fmt.parseInt(u64, trimmed, 10) catch gdrive_spool_default_limit_bytes;
}

fn makeAbsolutePath(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(raw)) return allocator.dupe(u8, raw);
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    return std.fs.path.join(allocator, &.{ cwd, raw });
}

fn detectUid() u32 {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.getuid()),
        else => 0,
    };
}

fn detectGid() u32 {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.getgid()),
        else => 0,
    };
}

fn sourceOperationForProtocolOp(op: fs_protocol.Op) ?fs_source_adapter.Operation {
    return switch (op) {
        .LOOKUP => .lookup,
        .GETATTR => .getattr,
        .READDIRP => .readdirp,
        .OPEN => .open,
        .READ => .read,
        .CLOSE => .close,
        .CREATE => .create,
        .WRITE => .write,
        .TRUNCATE => .truncate,
        .UNLINK => .unlink,
        .MKDIR => .mkdir,
        .RMDIR => .rmdir,
        .RENAME => .rename,
        .STATFS => .statfs,
        .SYMLINK => .symlink,
        .SETXATTR => .setxattr,
        .GETXATTR => .getxattr,
        .LISTXATTR => .listxattr,
        .REMOVEXATTR => .removexattr,
        .LOCK => .lock,
        .HELLO, .EXPORTS, .INVAL, .INVAL_DIR => null,
    };
}

fn sourceLookupChildAbsolute(
    source_kind: fs_source_adapter.SourceKind,
    allocator: std.mem.Allocator,
    root_path: []const u8,
    parent_path: []const u8,
    name: []const u8,
) !SourceLookupResult {
    return switch (source_kind) {
        .windows => blk: {
            const looked = try fs_windows_source_adapter.lookupChildAbsolute(allocator, root_path, parent_path, name);
            break :blk .{
                .resolved_path = looked.resolved_path,
                .stat = looked.stat,
            };
        },
        else => blk: {
            const looked = try fs_local_source_adapter.lookupChildAbsolute(allocator, root_path, parent_path, name);
            break :blk .{
                .resolved_path = looked.resolved_path,
                .stat = looked.stat,
            };
        },
    };
}

fn sourceStatAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8) !std.fs.File.Stat {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.statAbsolute(path),
        else => fs_local_source_adapter.statAbsolute(path),
    };
}

fn sourceOpenDirAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8) !std.fs.Dir {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.openDirAbsolute(path),
        else => fs_local_source_adapter.openDirAbsolute(path),
    };
}

fn sourceOpenAbsolute(
    source_kind: fs_source_adapter.SourceKind,
    path: []const u8,
    mode: std.fs.File.OpenMode,
) !SourceOpenResult {
    return switch (source_kind) {
        .windows => blk: {
            const opened = try fs_windows_source_adapter.openAbsolute(path, mode);
            break :blk .{
                .file = opened.file,
                .stat = opened.stat,
            };
        },
        else => blk: {
            const opened = try fs_local_source_adapter.openAbsolute(path, mode);
            break :blk .{
                .file = opened.file,
                .stat = opened.stat,
            };
        },
    };
}

fn sourceCreateExclusiveAbsolute(
    source_kind: fs_source_adapter.SourceKind,
    path: []const u8,
    mode: u32,
) !std.fs.File {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.createExclusiveAbsolute(path, mode),
        else => fs_local_source_adapter.createExclusiveAbsolute(path, mode),
    };
}

fn sourceRealpathAndStatAbsolute(
    source_kind: fs_source_adapter.SourceKind,
    allocator: std.mem.Allocator,
    path: []const u8,
) !SourceLookupResult {
    return switch (source_kind) {
        .windows => blk: {
            const looked = try fs_windows_source_adapter.realpathAndStatAbsolute(allocator, path);
            break :blk .{
                .resolved_path = looked.resolved_path,
                .stat = looked.stat,
            };
        },
        else => blk: {
            const looked = try fs_local_source_adapter.realpathAndStatAbsolute(allocator, path);
            break :blk .{
                .resolved_path = looked.resolved_path,
                .stat = looked.stat,
            };
        },
    };
}

fn sourceTruncateAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8, size: u64) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.truncateAbsolute(path, size),
        else => fs_local_source_adapter.truncateAbsolute(path, size),
    };
}

fn sourceDeleteFileAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.deleteFileAbsolute(path),
        else => fs_local_source_adapter.deleteFileAbsolute(path),
    };
}

fn sourceMakeDirAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.makeDirAbsolute(path),
        else => fs_local_source_adapter.makeDirAbsolute(path),
    };
}

fn sourceDeleteDirAbsolute(source_kind: fs_source_adapter.SourceKind, path: []const u8) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.deleteDirAbsolute(path),
        else => fs_local_source_adapter.deleteDirAbsolute(path),
    };
}

fn sourceRenameAbsolute(
    source_kind: fs_source_adapter.SourceKind,
    old_path: []const u8,
    new_path: []const u8,
) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.renameAbsolute(old_path, new_path),
        else => fs_local_source_adapter.renameAbsolute(old_path, new_path),
    };
}

fn sourceLockFile(
    source_kind: fs_source_adapter.SourceKind,
    file: *std.fs.File,
    mode: SourceLockMode,
    wait: bool,
) !void {
    return switch (source_kind) {
        .windows => fs_windows_source_adapter.lockFile(file, switch (mode) {
            .shared => .shared,
            .exclusive => .exclusive,
            .unlock => .unlock,
        }, wait),
        else => fs_local_source_adapter.lockFile(file, switch (mode) {
            .shared => .shared,
            .exclusive => .exclusive,
            .unlock => .unlock,
        }, wait),
    };
}

fn mapError(err: anyerror) DispatchResult {
    return switch (err) {
        error.GdriveAuthMissing => DispatchResult.failure(fs_protocol.Errno.EACCES, "missing gdrive access token"),
        error.GdriveAccessDenied => DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive access denied"),
        error.GdriveNotFound => DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found"),
        error.GdriveNotDirectory => DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "not a directory"),
        error.GdriveConflict => DispatchResult.failure(fs_protocol.Errno.EIO, "gdrive optimistic concurrency conflict"),
        error.GdriveRateLimited => DispatchResult.failure(fs_protocol.Errno.ETIMEDOUT, "gdrive rate limited"),
        error.GdriveInvalidResponse => DispatchResult.failure(fs_protocol.Errno.EIO, "gdrive invalid response"),
        error.GdriveUnexpectedStatus => DispatchResult.failure(fs_protocol.Errno.EIO, "gdrive unexpected status"),
        error.GdriveTokenRefreshFailed => DispatchResult.failure(fs_protocol.Errno.EACCES, "gdrive token refresh failed"),
        error.GdriveSpoolLimitExceeded => DispatchResult.failure(fs_protocol.Errno.ENOSPC, "gdrive spool limit exceeded"),
        error.AccessDenied => DispatchResult.failure(fs_protocol.Errno.EACCES, "access denied"),
        error.FileNotFound => DispatchResult.failure(fs_protocol.Errno.ENOENT, "file not found"),
        error.PathAlreadyExists => DispatchResult.failure(fs_protocol.Errno.EEXIST, "path exists"),
        error.NotDir => DispatchResult.failure(fs_protocol.Errno.ENOTDIR, "not a directory"),
        error.IsDir => DispatchResult.failure(fs_protocol.Errno.EISDIR, "is a directory"),
        error.DirectoryNotEmpty => DispatchResult.failure(fs_protocol.Errno.ENOTEMPTY, "directory not empty"),
        error.ReadOnlyFileSystem => DispatchResult.failure(fs_protocol.Errno.EROFS, "read-only filesystem"),
        error.NoData => DispatchResult.failure(fs_protocol.Errno.ENODATA, "no data"),
        error.WouldBlock => DispatchResult.failure(fs_protocol.Errno.EAGAIN, "would block"),
        error.OperationNotSupported => DispatchResult.failure(fs_protocol.Errno.ENOSYS, "operation not supported"),
        error.Range => DispatchResult.failure(fs_protocol.Errno.ERANGE, "range error"),
        error.NoSpaceLeft => DispatchResult.failure(fs_protocol.Errno.ENOSPC, "no space left"),
        error.InvalidHandle => DispatchResult.failure(fs_protocol.Errno.EBADF, "invalid handle"),
        error.InvalidArgument => DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid argument"),
        error.NameTooLong => DispatchResult.failure(fs_protocol.Errno.EINVAL, "name too long"),
        error.InvalidUtf8 => DispatchResult.failure(fs_protocol.Errno.EINVAL, "invalid utf8"),
        error.ConnectionTimedOut => DispatchResult.failure(fs_protocol.Errno.ETIMEDOUT, "timeout"),
        else => DispatchResult.failure(fs_protocol.Errno.EIO, @errorName(err)),
    };
}

fn parseResponseErrNo(json: []const u8) !i64 {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResponse;
    const err_obj = parsed.value.object.get("err") orelse return error.InvalidResponse;
    if (err_obj != .object) return error.InvalidResponse;
    const no = err_obj.object.get("no") orelse return error.InvalidResponse;
    if (no != .integer) return error.InvalidResponse;
    return no.integer;
}

test "fs_node_ops: mapError translates xattr and lock errno surface" {
    try std.testing.expectEqual(fs_protocol.Errno.ENODATA, mapError(error.NoData).err_no);
    try std.testing.expectEqual(fs_protocol.Errno.EAGAIN, mapError(error.WouldBlock).err_no);
    try std.testing.expectEqual(fs_protocol.Errno.ERANGE, mapError(error.Range).err_no);
    try std.testing.expectEqual(fs_protocol.Errno.ENOSYS, mapError(error.OperationNotSupported).err_no);
}

test "fs_node_ops: exports include configured root id" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .desc = "workspace", .ro = false },
    });
    defer node_ops.deinit();

    var req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer req.deinit();

    var result = node_ops.dispatch(req);
    defer result.deinit(allocator);

    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, result.err_no);
    try std.testing.expect(result.result_json != null);
    try std.testing.expect(std.mem.indexOf(u8, result.result_json.?, "\"exports\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.result_json.?, "\"source_kind\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.result_json.?, "\"source_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.result_json.?, "\"caps\"") != null);
}

test "fs_node_ops: gdrive spool reservation enforces configured limit" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .desc = "workspace", .ro = false },
    });
    defer node_ops.deinit();

    node_ops.gdrive_spool_max_bytes = 8;
    node_ops.gdrive_spool_bytes_in_use = 0;
    try node_ops.reserveGdriveSpool(5);
    try std.testing.expectEqual(@as(u64, 5), node_ops.gdrive_spool_bytes_in_use);
    try std.testing.expectError(error.GdriveSpoolLimitExceeded, node_ops.reserveGdriveSpool(4));
    node_ops.releaseGdriveSpool(3);
    try std.testing.expectEqual(@as(u64, 2), node_ops.gdrive_spool_bytes_in_use);
}

test "fs_node_ops: local-only exports skip gdrive spool setup" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .desc = "workspace", .ro = false },
    });
    defer node_ops.deinit();

    try std.testing.expect(node_ops.gdrive_spool_dir == null);
}

test "fs_node_ops: cleanupGdriveSpoolOrphans removes stale temp files" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .desc = "workspace", .ro = false },
        .{ .name = "cloud", .path = "primary", .source_kind = .gdrive },
    });
    defer node_ops.deinit();

    try std.testing.expect(node_ops.gdrive_spool_dir != null);
    const spool_dir = node_ops.gdrive_spool_dir.?;
    const stale_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}stale{d}{s}",
        .{ spool_dir, gdrive_spool_file_prefix, @as(u32, 1), gdrive_spool_file_suffix },
    );
    defer allocator.free(stale_path);

    var stale_file = try std.fs.createFileAbsolute(stale_path, .{ .read = true, .truncate = true });
    stale_file.close();
    try node_ops.cleanupGdriveSpoolOrphans();
    try std.testing.expectError(error.FileNotFound, std.fs.openFileAbsolute(stale_path, .{ .mode = .read_only }));
}

test "fs_node_ops: hello caps reflect mixed source capabilities" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "local",
            .path = root,
            .source_kind = .posix,
            .case_sensitive = true,
        },
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
            .case_sensitive = false,
        },
    });
    defer node_ops.deinit();

    var req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"HELLO\"}");
    defer req.deinit();
    var result = node_ops.dispatch(req);
    defer result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, result.err_no);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.result_json.?, .{});
    defer parsed.deinit();
    const caps = parsed.value.object.get("caps").?.object;
    try std.testing.expectEqual(false, caps.get("symlink").?.bool);
    try std.testing.expectEqual(false, caps.get("xattr").?.bool);
    try std.testing.expectEqual(false, caps.get("locks").?.bool);
    try std.testing.expectEqual(false, caps.get("case_sensitive").?.bool);
}

test "fs_node_ops: statfs returns source-aware block size" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const root = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "local",
            .path = root,
            .source_kind = .posix,
        },
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const exports = exports_parsed.value.object.get("exports").?.array.items;

    var local_root: ?u64 = null;
    var cloud_root: ?u64 = null;
    for (exports) |entry| {
        const obj = entry.object;
        const name = obj.get("name").?.string;
        const root_id: u64 = @intCast(obj.get("root").?.integer);
        if (std.mem.eql(u8, name, "local")) local_root = root_id;
        if (std.mem.eql(u8, name, "cloud")) cloud_root = root_id;
    }
    try std.testing.expect(local_root != null);
    try std.testing.expect(cloud_root != null);

    const local_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"STATFS\",\"node\":{d},\"a\":{{}}}}",
        .{local_root.?},
    );
    defer allocator.free(local_req_json);
    var local_req = try fs_protocol.parseRequest(allocator, local_req_json);
    defer local_req.deinit();
    var local_result = node_ops.dispatch(local_req);
    defer local_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, local_result.err_no);

    var local_parsed = try std.json.parseFromSlice(std.json.Value, allocator, local_result.result_json.?, .{});
    defer local_parsed.deinit();
    try std.testing.expectEqual(@as(i64, 4096), local_parsed.value.object.get("bsize").?.integer);

    const cloud_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"STATFS\",\"node\":{d},\"a\":{{}}}}",
        .{cloud_root.?},
    );
    defer allocator.free(cloud_req_json);
    var cloud_req = try fs_protocol.parseRequest(allocator, cloud_req_json);
    defer cloud_req.deinit();
    var cloud_result = node_ops.dispatch(cloud_req);
    defer cloud_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, cloud_result.err_no);

    var cloud_parsed = try std.json.parseFromSlice(std.json.Value, allocator, cloud_result.result_json.?, .{});
    defer cloud_parsed.deinit();
    try std.testing.expectEqual(@as(i64, 256 * 1024), cloud_parsed.value.object.get("bsize").?.integer);
}

test "fs_node_ops: exports honor source metadata overrides" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "portable",
            .path = root,
            .source_kind = .posix,
            .source_id = "posix:portable",
            .native_watch = false,
            .case_sensitive = false,
        },
    });
    defer node_ops.deinit();

    var req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer req.deinit();
    var result = node_ops.dispatch(req);
    defer result.deinit(allocator);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, result.result_json.?, .{});
    defer parsed.deinit();
    const export0 = parsed.value.object.get("exports").?.array.items[0].object;

    try std.testing.expectEqualStrings("posix", export0.get("source_kind").?.string);
    try std.testing.expectEqualStrings("posix:portable", export0.get("source_id").?.string);
    try std.testing.expectEqual(false, export0.get("caps").?.object.get("native_watch").?.bool);
    try std.testing.expectEqual(false, export0.get("caps").?.object.get("case_sensitive").?.bool);
    try std.testing.expectEqual(true, export0.get("caps").?.object.get("symlink").?.bool);
    try std.testing.expectEqual(true, export0.get("caps").?.object.get("xattr").?.bool);
    try std.testing.expectEqual(true, export0.get("caps").?.object.get("locks").?.bool);
    try std.testing.expectEqual(true, export0.get("caps").?.object.get("statfs").?.bool);
}

test "fs_node_ops: namespace exports scaffold synthetic control trees" {
    const allocator = std.testing.allocator;
    const meta_export_name = "spider-web-meta";
    const capabilities_export_name = "spider-web-capabilities";
    const jobs_export_name = "spider-web-jobs";

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = meta_export_name,
            .path = "meta",
            .source_kind = .namespace,
            .source_id = "meta",
            .ro = true,
        },
        .{
            .name = capabilities_export_name,
            .path = "capabilities",
            .source_kind = .namespace,
            .source_id = "capabilities",
            .ro = true,
        },
        .{
            .name = jobs_export_name,
            .path = "jobs",
            .source_kind = .namespace,
            .source_id = "jobs",
            .ro = false,
        },
    });
    defer node_ops.deinit();

    const meta_idx = node_ops.exportByName(meta_export_name).?;
    const capabilities_idx = node_ops.exportByName(capabilities_export_name).?;
    const meta_root = node_ops.exports.items[meta_idx].root_node_id;
    const capabilities_root = node_ops.exports.items[capabilities_idx].root_node_id;

    const meta_lookup_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":1,\"op\":\"LOOKUP\",\"node\":{d},\"a\":{{\"name\":\"protocol.json\"}}}}",
        .{meta_root},
    );
    defer allocator.free(meta_lookup_json);
    var meta_lookup = try fs_protocol.parseRequest(allocator, meta_lookup_json);
    defer meta_lookup.deinit();
    var meta_lookup_result = node_ops.dispatch(meta_lookup);
    defer meta_lookup_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, meta_lookup_result.err_no);

    const meta_create_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"CREATE\",\"node\":{d},\"a\":{{\"name\":\"illegal.txt\",\"mode\":33188,\"flags\":2}}}}",
        .{meta_root},
    );
    defer allocator.free(meta_create_json);
    var meta_create = try fs_protocol.parseRequest(allocator, meta_create_json);
    defer meta_create.deinit();
    var meta_create_result = node_ops.dispatch(meta_create);
    defer meta_create_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EROFS, meta_create_result.err_no);

    const cap_lookup_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"LOOKUP\",\"node\":{d},\"a\":{{\"name\":\"chat\"}}}}",
        .{capabilities_root},
    );
    defer allocator.free(cap_lookup_json);
    var cap_lookup = try fs_protocol.parseRequest(allocator, cap_lookup_json);
    defer cap_lookup.deinit();
    var cap_lookup_result = node_ops.dispatch(cap_lookup);
    defer cap_lookup_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, cap_lookup_result.err_no);
}

test "fs_node_ops: namespace jobs export supports create write read" {
    const allocator = std.testing.allocator;
    const jobs_export_name = "spider-web-jobs";

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = jobs_export_name,
            .path = "jobs",
            .source_kind = .namespace,
            .source_id = "jobs",
            .ro = false,
        },
    });
    defer node_ops.deinit();

    const jobs_idx = node_ops.exportByName(jobs_export_name).?;
    const jobs_root = node_ops.exports.items[jobs_idx].root_node_id;

    const create_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":1,\"op\":\"CREATE\",\"node\":{d},\"a\":{{\"name\":\"job-1.txt\",\"mode\":33188,\"flags\":2}}}}",
        .{jobs_root},
    );
    defer allocator.free(create_json);
    var create_req = try fs_protocol.parseRequest(allocator, create_json);
    defer create_req.deinit();
    var create_result = node_ops.dispatch(create_req);
    defer create_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, create_result.err_no);

    var create_parsed = try std.json.parseFromSlice(std.json.Value, allocator, create_result.result_json.?, .{});
    defer create_parsed.deinit();
    const node_id: u64 = @intCast(create_parsed.value.object.get("attr").?.object.get("id").?.integer);
    const handle_id: u64 = @intCast(create_parsed.value.object.get("h").?.integer);

    const write_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"WRITE\",\"h\":{d},\"a\":{{\"off\":0,\"data_b64\":\"aGVsbG8=\"}}}}",
        .{handle_id},
    );
    defer allocator.free(write_json);
    var write_req = try fs_protocol.parseRequest(allocator, write_json);
    defer write_req.deinit();
    var write_result = node_ops.dispatch(write_req);
    defer write_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, write_result.err_no);

    const close_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"CLOSE\",\"h\":{d}}}",
        .{handle_id},
    );
    defer allocator.free(close_json);
    var close_req = try fs_protocol.parseRequest(allocator, close_json);
    defer close_req.deinit();
    var close_result = node_ops.dispatch(close_req);
    defer close_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, close_result.err_no);

    const open_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":4,\"op\":\"OPEN\",\"node\":{d},\"a\":{{\"flags\":0}}}}",
        .{node_id},
    );
    defer allocator.free(open_json);
    var open_req = try fs_protocol.parseRequest(allocator, open_json);
    defer open_req.deinit();
    var open_result = node_ops.dispatch(open_req);
    defer open_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, open_result.err_no);

    var open_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_result.result_json.?, .{});
    defer open_parsed.deinit();
    const read_handle: u64 = @intCast(open_parsed.value.object.get("h").?.integer);

    const read_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":5,\"op\":\"READ\",\"h\":{d},\"a\":{{\"off\":0,\"len\":64}}}}",
        .{read_handle},
    );
    defer allocator.free(read_json);
    var read_req = try fs_protocol.parseRequest(allocator, read_json);
    defer read_req.deinit();
    var read_result = node_ops.dispatch(read_req);
    defer read_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, read_result.err_no);

    var read_parsed = try std.json.parseFromSlice(std.json.Value, allocator, read_result.result_json.?, .{});
    defer read_parsed.deinit();
    const encoded = read_parsed.value.object.get("data_b64").?.string;
    const decoded = try decodeBase64(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("hello", decoded);
}

test "fs_node_ops: gdrive scaffold supports read path and guards writes" {
    const allocator = std.testing.allocator;
    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const first = exports_parsed.value.object.get("exports").?.array.items[0].object;
    try std.testing.expectEqualStrings("gdrive", first.get("source_kind").?.string);
    try std.testing.expect(!first.get("ro").?.bool);
    try std.testing.expectEqual(false, first.get("caps").?.object.get("symlink").?.bool);
    try std.testing.expectEqual(false, first.get("caps").?.object.get("xattr").?.bool);
    try std.testing.expectEqual(false, first.get("caps").?.object.get("locks").?.bool);
    try std.testing.expectEqual(true, first.get("caps").?.object.get("statfs").?.bool);
    const root_id = first.get("root").?.integer;

    const lookup_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"LOOKUP\",\"node\":{d},\"a\":{{\"name\":\"{s}\"}}}}",
        .{ root_id, gdrive_status_name },
    );
    defer allocator.free(lookup_req_json);
    var lookup_req = try fs_protocol.parseRequest(allocator, lookup_req_json);
    defer lookup_req.deinit();
    var lookup_result = node_ops.dispatch(lookup_req);
    defer lookup_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, lookup_result.err_no);

    var lookup_parsed = try std.json.parseFromSlice(std.json.Value, allocator, lookup_result.result_json.?, .{});
    defer lookup_parsed.deinit();
    const status_id = lookup_parsed.value.object.get("attr").?.object.get("id").?.integer;

    const open_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"OPEN\",\"node\":{d},\"a\":{{\"flags\":0}}}}",
        .{status_id},
    );
    defer allocator.free(open_req_json);
    var open_req = try fs_protocol.parseRequest(allocator, open_req_json);
    defer open_req.deinit();
    var open_result = node_ops.dispatch(open_req);
    defer open_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, open_result.err_no);

    var open_parsed = try std.json.parseFromSlice(std.json.Value, allocator, open_result.result_json.?, .{});
    defer open_parsed.deinit();
    const handle_id = open_parsed.value.object.get("h").?.integer;

    const read_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":4,\"op\":\"READ\",\"h\":{d},\"a\":{{\"off\":0,\"len\":128}}}}",
        .{handle_id},
    );
    defer allocator.free(read_req_json);
    var read_req = try fs_protocol.parseRequest(allocator, read_req_json);
    defer read_req.deinit();
    var read_result = node_ops.dispatch(read_req);
    defer read_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, read_result.err_no);
    try std.testing.expect(std.mem.indexOf(u8, read_result.result_json.?, "\"data_b64\"") != null);

    const write_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":5,\"op\":\"WRITE\",\"h\":{d},\"a\":{{\"off\":0,\"data_b64\":\"aGVsbG8=\"}}}}",
        .{handle_id},
    );
    defer allocator.free(write_req_json);
    var write_req = try fs_protocol.parseRequest(allocator, write_req_json);
    defer write_req.deinit();
    var write_result = node_ops.dispatch(write_req);
    defer write_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EROFS, write_result.err_no);

    const mkdir_status_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":7,\"op\":\"MKDIR\",\"node\":{d},\"a\":{{\"name\":\"{s}\"}}}}",
        .{ root_id, gdrive_status_name },
    );
    defer allocator.free(mkdir_status_req_json);
    var mkdir_status_req = try fs_protocol.parseRequest(allocator, mkdir_status_req_json);
    defer mkdir_status_req.deinit();
    var mkdir_status_result = node_ops.dispatch(mkdir_status_req);
    defer mkdir_status_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EROFS, mkdir_status_result.err_no);

    const create_status_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":8,\"op\":\"CREATE\",\"node\":{d},\"a\":{{\"name\":\"{s}\",\"mode\":33188,\"flags\":2}}}}",
        .{ root_id, gdrive_status_name },
    );
    defer allocator.free(create_status_req_json);
    var create_status_req = try fs_protocol.parseRequest(allocator, create_status_req_json);
    defer create_status_req.deinit();
    var create_status_result = node_ops.dispatch(create_status_req);
    defer create_status_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EROFS, create_status_result.err_no);

    const truncate_root_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":9,\"op\":\"TRUNCATE\",\"node\":{d},\"a\":{{\"sz\":0}}}}",
        .{root_id},
    );
    defer allocator.free(truncate_root_req_json);
    var truncate_root_req = try fs_protocol.parseRequest(allocator, truncate_root_req_json);
    defer truncate_root_req.deinit();
    var truncate_root_result = node_ops.dispatch(truncate_root_req);
    defer truncate_root_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EISDIR, truncate_root_result.err_no);

    const close_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":10,\"op\":\"CLOSE\",\"h\":{d}}}",
        .{handle_id},
    );
    defer allocator.free(close_req_json);
    var close_req = try fs_protocol.parseRequest(allocator, close_req_json);
    defer close_req.deinit();
    var close_result = node_ops.dispatch(close_req);
    defer close_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, close_result.err_no);
}

test "fs_node_ops: adapter capability gate rejects unsupported gdrive xattr operation" {
    const allocator = std.testing.allocator;
    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer parsed.deinit();
    const root_id = parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"LISTXATTR\",\"node\":{d},\"a\":{{}}}}",
        .{root_id},
    );
    defer allocator.free(req_json);
    var req = try fs_protocol.parseRequest(allocator, req_json);
    defer req.deinit();
    var result = node_ops.dispatch(req);
    defer result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.ENOSYS, result.err_no);
}

test "fs_node_ops: windows source kind follows host capability" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    if (builtin.os.tag == .windows) {
        var windows_ops = try NodeOps.init(allocator, &[_]ExportSpec{
            .{
                .name = "win",
                .path = root,
                .source_kind = .windows,
            },
        });
        windows_ops.deinit();
    } else {
        try std.testing.expectError(error.UnsupportedSourceHost, NodeOps.init(allocator, &[_]ExportSpec{
            .{
                .name = "win",
                .path = root,
                .source_kind = .windows,
            },
        }));
    }
}

test "fs_node_ops: windows source readdirp lists regular files" {
    if (builtin.os.tag != .windows) return;

    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    try temp.dir.writeFile(.{ .sub_path = "hello.txt", .data = "hello" });

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "win",
            .path = root,
            .source_kind = .windows,
        },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const readdir_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"READDIRP\",\"node\":{d},\"a\":{{\"cookie\":0,\"max\":128}}}}",
        .{root_id},
    );
    defer allocator.free(readdir_req_json);

    var readdir_req = try fs_protocol.parseRequest(allocator, readdir_req_json);
    defer readdir_req.deinit();
    var readdir_result = node_ops.dispatch(readdir_req);
    defer readdir_result.deinit(allocator);

    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, readdir_result.err_no);
    try std.testing.expect(std.mem.indexOf(u8, readdir_result.result_json.?, "\"hello.txt\"") != null);
}

test "fs_node_ops: read-only export rejects mkdir" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    const cwd_path = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "ro", .path = cwd_path, .ro = true },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);
    const exports_json = exports_result.result_json.?;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_json, .{});
    defer parsed.deinit();
    const first = parsed.value.object.get("exports").?.array.items[0];
    const root_id = first.object.get("root").?.integer;

    const req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"MKDIR\",\"node\":{d},\"a\":{{\"name\":\"new-dir\"}}}}",
        .{root_id},
    );
    defer allocator.free(req_json);

    var mkdir_req = try fs_protocol.parseRequest(allocator, req_json);
    defer mkdir_req.deinit();
    const mkdir_result = node_ops.dispatch(mkdir_req);
    try std.testing.expectEqual(fs_protocol.Errno.EROFS, mkdir_result.err_no);
}

test "fs_node_ops: readdir includes regular files" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    try temp.dir.writeFile(.{ .sub_path = "hello.txt", .data = "hello" });

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    {
        var dir = try std.fs.openDirAbsolute(root, .{ .iterate = true });
        defer dir.close();
        var it = dir.iterate();
        var saw = false;
        while (try it.next()) |entry| {
            if (std.mem.eql(u8, entry.name, "hello.txt")) saw = true;
        }
        try std.testing.expect(saw);
    }

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"READDIRP\",\"node\":{d},\"a\":{{\"cookie\":0,\"max\":128}}}}",
        .{root_id},
    );
    defer allocator.free(req_json);

    var readdir_req = try fs_protocol.parseRequest(allocator, req_json);
    defer readdir_req.deinit();
    var readdir_result = node_ops.dispatch(readdir_req);
    defer readdir_result.deinit(allocator);

    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, readdir_result.err_no);
    try std.testing.expect(std.mem.indexOf(u8, readdir_result.result_json.?, "\"hello.txt\"") != null);
}

test "fs_node_ops: local export hides sandbox runtime folder" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    try temp.dir.writeFile(.{ .sub_path = "hello.txt", .data = "hello" });
    try temp.dir.makePath(".spiderweb-sandbox/mounts/system");
    try temp.dir.writeFile(.{ .sub_path = ".spiderweb-sandbox/mounts/system/ignore.txt", .data = "hidden" });

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);

    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const readdir_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"READDIRP\",\"node\":{d},\"a\":{{\"cookie\":0,\"max\":128}}}}",
        .{root_id},
    );
    defer allocator.free(readdir_json);
    var readdir_req = try fs_protocol.parseRequest(allocator, readdir_json);
    defer readdir_req.deinit();
    var readdir_result = node_ops.dispatch(readdir_req);
    defer readdir_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, readdir_result.err_no);
    try std.testing.expect(std.mem.indexOf(u8, readdir_result.result_json.?, "\"hello.txt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, readdir_result.result_json.?, "\".spiderweb-sandbox\"") == null);

    const lookup_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"LOOKUP\",\"node\":{d},\"a\":{{\"name\":\".spiderweb-sandbox\"}}}}",
        .{root_id},
    );
    defer allocator.free(lookup_json);
    var lookup_req = try fs_protocol.parseRequest(allocator, lookup_json);
    defer lookup_req.deinit();
    const lookup_result = node_ops.dispatch(lookup_req);
    try std.testing.expectEqual(fs_protocol.Errno.ENOENT, lookup_result.err_no);
}

test "fs_node_ops: local readdir paging skips hidden entries without duplicates" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    try temp.dir.writeFile(.{ .sub_path = "alpha.txt", .data = "a" });
    try temp.dir.writeFile(.{ .sub_path = "beta.txt", .data = "b" });
    try temp.dir.makePath(".spiderweb-sandbox/mounts/system");

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer node_ops.deinit();

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    var seen = std.StringHashMapUnmanaged(void){};
    defer {
        var it = seen.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        seen.deinit(allocator);
    }

    var cookie: u64 = 0;
    var page: usize = 0;
    var done = false;
    while (!done and page < 32) : (page += 1) {
        const req_json = try std.fmt.allocPrint(
            allocator,
            "{{\"t\":\"req\",\"id\":{d},\"op\":\"READDIRP\",\"node\":{d},\"a\":{{\"cookie\":{d},\"max\":1}}}}",
            .{ page + 10, root_id, cookie },
        );
        defer allocator.free(req_json);
        var readdir_req = try fs_protocol.parseRequest(allocator, req_json);
        defer readdir_req.deinit();
        var readdir_result = node_ops.dispatch(readdir_req);
        defer readdir_result.deinit(allocator);
        try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, readdir_result.err_no);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, readdir_result.result_json.?, .{});
        defer parsed.deinit();
        const ents = parsed.value.object.get("ents").?.array.items;
        for (ents) |entry| {
            const name = entry.object.get("name").?.string;
            try std.testing.expect(!std.mem.eql(u8, name, ".spiderweb-sandbox"));
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            try std.testing.expect(!seen.contains(name));
            try seen.put(allocator, try allocator.dupe(u8, name), {});
        }

        cookie = @intCast(parsed.value.object.get("next").?.integer);
        done = parsed.value.object.get("eof").?.bool;
    }

    try std.testing.expect(done);
    try std.testing.expect(seen.contains("alpha.txt"));
    try std.testing.expect(seen.contains("beta.txt"));
}

test "fs_node_ops: filesystem watcher reports out-of-band mutations" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();

    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{ .name = "work", .path = root, .ro = false },
    });
    defer node_ops.deinit();

    const baseline = try node_ops.pollFilesystemInvalidations(allocator, 256);
    defer allocator.free(baseline);
    try std.testing.expectEqual(@as(usize, 0), baseline.len);

    const root_id = node_ops.exports.items[0].root_node_id;
    try temp.dir.writeFile(.{ .sub_path = "external.txt", .data = "x" });

    const created = try node_ops.pollFilesystemInvalidations(allocator, 256);
    defer allocator.free(created);
    try std.testing.expect(created.len > 0);

    var saw_root_dir_inval = false;
    for (created) |event| {
        if (event == .INVAL_DIR and event.INVAL_DIR.dir == root_id) {
            saw_root_dir_inval = true;
            break;
        }
    }
    try std.testing.expect(saw_root_dir_inval);

    try temp.dir.writeFile(.{ .sub_path = "external.txt", .data = "xx" });
    const updated = try node_ops.pollFilesystemInvalidations(allocator, 256);
    defer allocator.free(updated);
    try std.testing.expect(updated.len > 0);
}

test "fs_node_ops: default gdrive credential handle is sanitized" {
    const allocator = std.testing.allocator;
    const handle = try defaultGdriveCredentialHandle(allocator, "team drive@prod");
    defer allocator.free(handle);
    try std.testing.expectEqualStrings("gdrive.team-drive-prod", handle);
}

test "fs_node_ops: parse gdrive oauth state bundle" {
    const allocator = std.testing.allocator;
    const raw =
        \\{
        \\  "kind":"google_oauth",
        \\  "client_id":"cid",
        \\  "client_secret":"sec",
        \\  "refresh_token":"ref",
        \\  "access_token":"acc",
        \\  "expires_at_ms":12345
        \\}
    ;

    var state = try parseGdriveOauthState(allocator, raw);
    defer state.deinit(allocator);

    try std.testing.expectEqualStrings("cid", state.client_id);
    try std.testing.expectEqualStrings("sec", state.client_secret);
    try std.testing.expectEqualStrings("ref", state.refresh_token);
    try std.testing.expectEqualStrings("acc", state.access_token.?);
    try std.testing.expectEqual(@as(u64, 12345), state.expires_at_ms);
}

test "fs_node_ops: gdrive change state bundle roundtrip" {
    const allocator = std.testing.allocator;
    const serialized = try serializeGdriveChangeStateBundle(
        allocator,
        "gdrive:team",
        "page-token-123",
        999,
    );
    defer allocator.free(serialized);

    var parsed = try parseGdriveChangeStateBundle(allocator, serialized);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("page-token-123", parsed.page_token);
    try std.testing.expectEqual(@as(u64, 999), parsed.updated_at_ms);
    try std.testing.expectEqualStrings("gdrive:team", parsed.source_id.?);
}

test "fs_node_ops: gdrive change persistence handle sanitizes source id" {
    const allocator = std.testing.allocator;
    const handle = try buildGdriveChangePersistHandle(allocator, "gdrive:team drive@prod");
    defer allocator.free(handle);
    try std.testing.expectEqualStrings("gdrive.changes.gdrive-team-drive-prod", handle);
}

test "fs_node_ops: gdrive invalidation poll is safe without api token" {
    const allocator = std.testing.allocator;
    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();

    const first = try node_ops.pollFilesystemInvalidations(allocator, 256);
    defer allocator.free(first);
    try std.testing.expectEqual(@as(usize, 0), first.len);

    const second = try node_ops.pollFilesystemInvalidations(allocator, 256);
    defer allocator.free(second);
    try std.testing.expectEqual(@as(usize, 0), second.len);
}

const GdriveApiMockCtx = struct {
    create_calls: usize = 0,
    stat_calls: usize = 0,
    resumable_init_calls: usize = 0,
    upload_put_calls: usize = 0,
};

fn gdriveApiMockHandler(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    method: fs_gdrive_backend.HttpMethod,
    url: []const u8,
    payload: ?[]const u8,
    headers: []const std.http.Header,
) anyerror!fs_gdrive_backend.MockResponse {
    _ = allocator;
    _ = payload;
    _ = headers;
    const ctx: *GdriveApiMockCtx = @ptrCast(@alignCast(raw_ctx.?));

    if (method == .POST and std.mem.indexOf(u8, url, "/drive/v3/files?supportsAllDrives=true") != null and
        std.mem.indexOf(u8, url, "uploadType=") == null)
    {
        ctx.create_calls += 1;
        return .{
            .status = .created,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"0\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"1\"}",
        };
    }

    if (method == .GET and std.mem.indexOf(u8, url, "/drive/v3/files/file-1?supportsAllDrives=true&fields=") != null) {
        ctx.stat_calls += 1;
        return .{
            .status = .ok,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"0\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"1\"}",
        };
    }

    if (method == .PATCH and std.mem.indexOf(u8, url, "/upload/drive/v3/files/file-1?uploadType=resumable") != null) {
        ctx.resumable_init_calls += 1;
        return .{
            .status = .ok,
            .location = "https://upload.mock/session/node-ops",
        };
    }

    if (method == .PUT and std.mem.eql(u8, url, "https://upload.mock/session/node-ops")) {
        ctx.upload_put_calls += 1;
        return .{
            .status = .ok,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"5\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"2\"}",
        };
    }

    return error.GdriveUnexpectedStatus;
}

test "fs_node_ops: gdrive create write close uses mocked Drive API" {
    const allocator = std.testing.allocator;
    var ctx = GdriveApiMockCtx{};
    fs_gdrive_backend.setTestTransport(.{
        .ctx = &ctx,
        .handler = gdriveApiMockHandler,
    });
    defer fs_gdrive_backend.setTestTransport(null);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();
    node_ops.gdrive_backend_enabled = true;
    if (node_ops.gdrive_env_access_token) |old| allocator.free(old);
    node_ops.gdrive_env_access_token = try allocator.dupe(u8, "mock-token");

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const create_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"CREATE\",\"node\":{d},\"a\":{{\"name\":\"note.txt\",\"mode\":33188,\"flags\":2}}}}",
        .{root_id},
    );
    defer allocator.free(create_req_json);
    var create_req = try fs_protocol.parseRequest(allocator, create_req_json);
    defer create_req.deinit();
    var create_result = node_ops.dispatch(create_req);
    defer create_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, create_result.err_no);

    var create_parsed = try std.json.parseFromSlice(std.json.Value, allocator, create_result.result_json.?, .{});
    defer create_parsed.deinit();
    const handle_id = create_parsed.value.object.get("h").?.integer;

    const write_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"WRITE\",\"h\":{d},\"a\":{{\"off\":0,\"data_b64\":\"aGVsbG8=\"}}}}",
        .{handle_id},
    );
    defer allocator.free(write_req_json);
    var write_req = try fs_protocol.parseRequest(allocator, write_req_json);
    defer write_req.deinit();
    var write_result = node_ops.dispatch(write_req);
    defer write_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, write_result.err_no);

    const close_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":4,\"op\":\"CLOSE\",\"h\":{d}}}",
        .{handle_id},
    );
    defer allocator.free(close_req_json);
    var close_req = try fs_protocol.parseRequest(allocator, close_req_json);
    defer close_req.deinit();
    var close_result = node_ops.dispatch(close_req);
    defer close_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, close_result.err_no);

    try std.testing.expectEqual(@as(usize, 1), ctx.create_calls);
    try std.testing.expectEqual(@as(usize, 1), ctx.stat_calls);
    try std.testing.expectEqual(@as(usize, 1), ctx.resumable_init_calls);
    try std.testing.expectEqual(@as(usize, 1), ctx.upload_put_calls);
}

const GdriveConflictMockCtx = struct {
    create_calls: usize = 0,
    stat_calls: usize = 0,
    resumable_init_calls: usize = 0,
    upload_put_calls: usize = 0,
};

fn gdriveConflictMockHandler(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    method: fs_gdrive_backend.HttpMethod,
    url: []const u8,
    payload: ?[]const u8,
    headers: []const std.http.Header,
) anyerror!fs_gdrive_backend.MockResponse {
    _ = allocator;
    _ = payload;
    _ = headers;
    const ctx: *GdriveConflictMockCtx = @ptrCast(@alignCast(raw_ctx.?));

    if (method == .POST and std.mem.indexOf(u8, url, "/drive/v3/files?supportsAllDrives=true") != null and
        std.mem.indexOf(u8, url, "uploadType=") == null)
    {
        ctx.create_calls += 1;
        return .{
            .status = .created,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"0\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"1\"}",
        };
    }

    if (method == .GET and std.mem.indexOf(u8, url, "/drive/v3/files/file-1?supportsAllDrives=true&fields=") != null) {
        ctx.stat_calls += 1;
        return .{
            .status = .ok,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"3\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"2\"}",
        };
    }

    if (method == .PATCH and std.mem.indexOf(u8, url, "/upload/drive/v3/files/file-1?uploadType=resumable") != null) {
        ctx.resumable_init_calls += 1;
        return .{
            .status = .ok,
            .location = "https://upload.mock/session/conflict",
        };
    }

    if (method == .PUT and std.mem.eql(u8, url, "https://upload.mock/session/conflict")) {
        ctx.upload_put_calls += 1;
        return .{
            .status = .ok,
            .body = "{\"id\":\"file-1\",\"name\":\"note.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"primary\"],\"size\":\"3\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"3\"}",
        };
    }

    return error.GdriveUnexpectedStatus;
}

test "fs_node_ops: gdrive close rejects optimistic concurrency conflict" {
    const allocator = std.testing.allocator;
    var ctx = GdriveConflictMockCtx{};
    fs_gdrive_backend.setTestTransport(.{
        .ctx = &ctx,
        .handler = gdriveConflictMockHandler,
    });
    defer fs_gdrive_backend.setTestTransport(null);

    var node_ops = try NodeOps.init(allocator, &[_]ExportSpec{
        .{
            .name = "cloud",
            .path = "primary",
            .source_kind = .gdrive,
        },
    });
    defer node_ops.deinit();
    node_ops.gdrive_backend_enabled = true;
    if (node_ops.gdrive_env_access_token) |old| allocator.free(old);
    node_ops.gdrive_env_access_token = try allocator.dupe(u8, "mock-token");

    var exports_req = try fs_protocol.parseRequest(allocator, "{\"t\":\"req\",\"id\":1,\"op\":\"EXPORTS\"}");
    defer exports_req.deinit();
    var exports_result = node_ops.dispatch(exports_req);
    defer exports_result.deinit(allocator);
    var exports_parsed = try std.json.parseFromSlice(std.json.Value, allocator, exports_result.result_json.?, .{});
    defer exports_parsed.deinit();
    const root_id = exports_parsed.value.object.get("exports").?.array.items[0].object.get("root").?.integer;

    const create_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":2,\"op\":\"CREATE\",\"node\":{d},\"a\":{{\"name\":\"note.txt\",\"mode\":33188,\"flags\":2}}}}",
        .{root_id},
    );
    defer allocator.free(create_req_json);
    var create_req = try fs_protocol.parseRequest(allocator, create_req_json);
    defer create_req.deinit();
    var create_result = node_ops.dispatch(create_req);
    defer create_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, create_result.err_no);

    var create_parsed = try std.json.parseFromSlice(std.json.Value, allocator, create_result.result_json.?, .{});
    defer create_parsed.deinit();
    const handle_id = create_parsed.value.object.get("h").?.integer;

    const write_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":3,\"op\":\"WRITE\",\"h\":{d},\"a\":{{\"off\":0,\"data_b64\":\"YWJj\"}}}}",
        .{handle_id},
    );
    defer allocator.free(write_req_json);
    var write_req = try fs_protocol.parseRequest(allocator, write_req_json);
    defer write_req.deinit();
    var write_result = node_ops.dispatch(write_req);
    defer write_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.SUCCESS, write_result.err_no);

    const close_req_json = try std.fmt.allocPrint(
        allocator,
        "{{\"t\":\"req\",\"id\":4,\"op\":\"CLOSE\",\"h\":{d}}}",
        .{handle_id},
    );
    defer allocator.free(close_req_json);
    var close_req = try fs_protocol.parseRequest(allocator, close_req_json);
    defer close_req.deinit();
    var close_result = node_ops.dispatch(close_req);
    defer close_result.deinit(allocator);
    try std.testing.expectEqual(fs_protocol.Errno.EIO, close_result.err_no);

    try std.testing.expectEqual(@as(usize, 1), ctx.create_calls);
    try std.testing.expectEqual(@as(usize, 1), ctx.stat_calls);
    try std.testing.expectEqual(@as(usize, 0), ctx.resumable_init_calls);
    try std.testing.expectEqual(@as(usize, 0), ctx.upload_put_calls);
}
