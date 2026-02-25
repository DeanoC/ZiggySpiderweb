const std = @import("std");
const ltm_store = @import("ziggy-memory-store").ltm_store;

const persistence_base_id = "spiderweb:control-plane:state";
const persistence_kind = "control_plane_state_v1";
const persistence_key_env = "SPIDERWEB_CONTROL_STATE_KEY_HEX";
const persistence_cipher = std.crypto.aead.aes_gcm.Aes256Gcm;
const persistence_aad = "spiderweb-control-plane-state-v1";
pub const spider_web_project_id = "spider-web";
const spider_web_project_name = "Spider Web";
const spider_web_project_status = "active";
const spider_web_project_vision = "System project for Spiderweb control and host integrations";
const spider_web_workspace_mount_path = "/workspace";
const spider_web_project_kind_name = "spider_web_builtin";
const normal_project_kind_name = "normal";
const default_primary_agent_id = "default";
const default_spider_web_root = "/";

const ProjectKind = enum {
    normal,
    spider_web_builtin,
};

pub const ControlPlaneError = error{
    InvalidPayload,
    MissingField,
    InviteNotFound,
    InviteExpired,
    InviteRedeemed,
    NodeNotFound,
    NodeAuthFailed,
    ProjectNotFound,
    ProjectAuthFailed,
    ProjectProtected,
    ProjectAssignmentForbidden,
    MountConflict,
    MountNotFound,
};

pub const SpiderWebMountSpec = struct {
    mount_path: []const u8,
    export_name: []const u8,
};

const Invite = struct {
    id: []u8,
    token: []u8,
    created_at_ms: i64,
    expires_at_ms: i64,
    redeemed: bool = false,

    fn deinit(self: *Invite, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.token);
        self.* = undefined;
    }
};

const Node = struct {
    id: []u8,
    name: []u8,
    fs_url: []u8,
    secret: []u8,
    lease_token: []u8,
    joined_at_ms: i64,
    last_seen_ms: i64,
    lease_expires_at_ms: i64,

    fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.fs_url);
        allocator.free(self.secret);
        allocator.free(self.lease_token);
        self.* = undefined;
    }
};

const ProjectMount = struct {
    mount_path: []u8,
    node_id: []u8,
    export_name: []u8,

    fn deinit(self: *ProjectMount, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        allocator.free(self.node_id);
        allocator.free(self.export_name);
        self.* = undefined;
    }
};

const Project = struct {
    id: []u8,
    name: []u8,
    vision: []u8,
    status: []u8,
    kind: ProjectKind = .normal,
    is_delete_protected: bool = false,
    mutation_token: []u8,
    created_at_ms: i64,
    updated_at_ms: i64,
    mounts: std.ArrayListUnmanaged(ProjectMount) = .{},

    fn deinit(self: *Project, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.vision);
        allocator.free(self.status);
        allocator.free(self.mutation_token);
        for (self.mounts.items) |*mount| mount.deinit(allocator);
        self.mounts.deinit(allocator);
        self.* = undefined;
    }
};

const ReconcileState = enum {
    idle,
    pending,
    running,
    degraded,
};

const DriftSeverity = enum {
    info,
    warning,
    err,
};

const ReconcileProjectSummary = struct {
    drift_count: u32 = 0,
    queue_depth: u32 = 0,
};

pub const ControlPlane = struct {
    allocator: std.mem.Allocator,
    primary_agent_id: []const u8 = default_primary_agent_id,
    spider_web_root: []const u8 = default_spider_web_root,
    store: ?*ltm_store.VersionedMemStore = null,
    state_encryption_key: ?[persistence_cipher.key_length]u8 = null,
    mutex: std.Thread.Mutex = .{},

    invites: std.StringHashMapUnmanaged(Invite) = .{},
    nodes: std.StringHashMapUnmanaged(Node) = .{},
    projects: std.StringHashMapUnmanaged(Project) = .{},
    active_project_by_agent: std.StringHashMapUnmanaged([]u8) = .{},

    next_invite_id: u64 = 1,
    next_node_id: u64 = 1,
    next_project_id: u64 = 1,

    invites_created_total: u64 = 0,
    invites_redeemed_total: u64 = 0,
    node_joins_total: u64 = 0,
    node_lease_refresh_total: u64 = 0,
    nodes_ensured_total: u64 = 0,
    node_deletes_total: u64 = 0,
    project_creates_total: u64 = 0,
    project_updates_total: u64 = 0,
    project_deletes_total: u64 = 0,
    mount_sets_total: u64 = 0,
    mount_removes_total: u64 = 0,
    project_token_rotates_total: u64 = 0,
    project_token_revokes_total: u64 = 0,
    project_activations_total: u64 = 0,
    lease_reap_nodes_total: u64 = 0,

    reconcile_state: ReconcileState = .pending,
    reconcile_last_reconcile_ms: i64 = 0,
    reconcile_last_success_ms: i64 = 0,
    reconcile_last_error: ?[]u8 = null,
    reconcile_queue_depth: u32 = 0,
    reconcile_failed_ops_total: u64 = 0,
    reconcile_cycles_total: u64 = 0,
    reconcile_requested_at_ms: i64 = 0,
    reconcile_debounce_ms: i64 = 250,
    reconcile_retry_backoff_ms: i64 = 100,
    reconcile_max_retries_per_cycle: u32 = 3,
    reconcile_last_failed_ops: std.ArrayListUnmanaged([]u8) = .{},

    pub const InitOptions = struct {
        primary_agent_id: []const u8 = default_primary_agent_id,
        spider_web_root: []const u8 = default_spider_web_root,
    };

    pub fn init(allocator: std.mem.Allocator) ControlPlane {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, options: InitOptions) ControlPlane {
        const primary_agent_id = if (std.mem.trim(u8, options.primary_agent_id, " \t\r\n").len > 0)
            options.primary_agent_id
        else
            default_primary_agent_id;
        const spider_web_root = if (std.mem.trim(u8, options.spider_web_root, " \t\r\n").len > 0)
            options.spider_web_root
        else
            default_spider_web_root;
        var plane: ControlPlane = .{
            .allocator = allocator,
            .primary_agent_id = primary_agent_id,
            .spider_web_root = spider_web_root,
        };
        plane.ensureBuiltinProjectBestEffortLocked(std.time.milliTimestamp());
        return plane;
    }

    pub fn initWithPersistence(
        allocator: std.mem.Allocator,
        ltm_directory: []const u8,
        ltm_filename: []const u8,
    ) ControlPlane {
        return initWithPersistenceOptions(allocator, ltm_directory, ltm_filename, .{});
    }

    pub fn initWithPersistenceOptions(
        allocator: std.mem.Allocator,
        ltm_directory: []const u8,
        ltm_filename: []const u8,
        options: InitOptions,
    ) ControlPlane {
        var plane = ControlPlane.initWithOptions(allocator, options);
        plane.state_encryption_key = loadStateEncryptionKey(allocator);
        if (ltm_directory.len == 0 or ltm_filename.len == 0) {
            plane.ensureBuiltinProjectBestEffortLocked(std.time.milliTimestamp());
            return plane;
        }

        const store_ptr = allocator.create(ltm_store.VersionedMemStore) catch |err| {
            std.log.warn("control-plane persistence disabled: {s}", .{@errorName(err)});
            plane.ensureBuiltinProjectBestEffortLocked(std.time.milliTimestamp());
            return plane;
        };
        errdefer allocator.destroy(store_ptr);

        store_ptr.* = ltm_store.VersionedMemStore.open(allocator, ltm_directory, ltm_filename) catch |err| {
            std.log.warn("control-plane persistence disabled: {s}", .{@errorName(err)});
            allocator.destroy(store_ptr);
            plane.ensureBuiltinProjectBestEffortLocked(std.time.milliTimestamp());
            return plane;
        };
        plane.store = store_ptr;

        plane.loadSnapshotLocked() catch |err| {
            plane.clearState();
            plane.next_invite_id = 1;
            plane.next_node_id = 1;
            plane.next_project_id = 1;
            std.log.warn("control-plane snapshot load failed: {s}", .{@errorName(err)});
        };
        plane.ensureBuiltinProjectBestEffortLocked(std.time.milliTimestamp());
        return plane;
    }

    fn ensureBuiltinProjectBestEffortLocked(self: *ControlPlane, now_ms: i64) void {
        self.ensureBuiltinSpiderWebProjectLocked(now_ms) catch |err| {
            std.log.warn("control-plane builtin project ensure failed: {s}", .{@errorName(err)});
        };
    }

    fn ensureBuiltinSpiderWebProjectLocked(self: *ControlPlane, now_ms: i64) !void {
        var changed = false;
        if (self.projects.getPtr(spider_web_project_id)) |project| {
            if (project.kind != .spider_web_builtin) {
                project.kind = .spider_web_builtin;
                changed = true;
            }
            if (!project.is_delete_protected) {
                project.is_delete_protected = true;
                changed = true;
            }
            if (!std.mem.eql(u8, project.status, spider_web_project_status)) {
                self.allocator.free(project.status);
                project.status = try self.allocator.dupe(u8, spider_web_project_status);
                changed = true;
            }
            if (project.name.len == 0) {
                self.allocator.free(project.name);
                project.name = try self.allocator.dupe(u8, spider_web_project_name);
                changed = true;
            }
            if (changed) project.updated_at_ms = now_ms;
        } else {
            const project = Project{
                .id = try self.allocator.dupe(u8, spider_web_project_id),
                .name = try self.allocator.dupe(u8, spider_web_project_name),
                .vision = try self.allocator.dupe(u8, spider_web_project_vision),
                .status = try self.allocator.dupe(u8, spider_web_project_status),
                .kind = .spider_web_builtin,
                .is_delete_protected = true,
                .mutation_token = try makeToken(self.allocator, "proj"),
                .created_at_ms = now_ms,
                .updated_at_ms = now_ms,
            };
            errdefer {
                self.allocator.free(project.id);
                self.allocator.free(project.name);
                self.allocator.free(project.vision);
                self.allocator.free(project.status);
                self.allocator.free(project.mutation_token);
            }
            try self.projects.put(self.allocator, project.id, project);
            changed = true;
        }

        var active_it = self.active_project_by_agent.iterator();
        while (active_it.next()) |entry| {
            if (!std.mem.eql(u8, entry.value_ptr.*, spider_web_project_id)) continue;
            if (std.mem.eql(u8, entry.key_ptr.*, self.primary_agent_id)) continue;
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = try self.allocator.dupe(u8, "");
            changed = true;
        }

        if (changed and self.store != null) self.persistSnapshotBestEffortLocked();
    }

    pub fn ensureSpiderWebMount(self: *ControlPlane, node_id: []const u8, export_name: []const u8) !void {
        const mount_specs = [_]SpiderWebMountSpec{
            .{ .mount_path = spider_web_workspace_mount_path, .export_name = export_name },
        };
        return self.ensureSpiderWebMounts(node_id, &mount_specs);
    }

    pub fn ensureSpiderWebMounts(
        self: *ControlPlane,
        node_id: []const u8,
        mount_specs: []const SpiderWebMountSpec,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        try validateIdentifier(node_id, 128);
        if (mount_specs.len == 0) return ControlPlaneError.MissingField;
        if (!self.nodes.contains(node_id)) return ControlPlaneError.NodeNotFound;
        try self.ensureBuiltinSpiderWebProjectLocked(now_ms);
        const project = self.projects.getPtr(spider_web_project_id) orelse return ControlPlaneError.ProjectNotFound;

        var normalized_paths = std.ArrayListUnmanaged([]u8){};
        defer {
            for (normalized_paths.items) |path| self.allocator.free(path);
            normalized_paths.deinit(self.allocator);
        }

        for (mount_specs) |spec| {
            try validateExportName(spec.export_name);
            const normalized = try normalizeMountPath(self.allocator, spec.mount_path);
            errdefer self.allocator.free(normalized);
            for (normalized_paths.items) |existing| {
                if (std.mem.eql(u8, existing, normalized)) {
                    self.allocator.free(normalized);
                    return ControlPlaneError.MountConflict;
                }
                if (mountPathsOverlap(existing, normalized)) {
                    self.allocator.free(normalized);
                    return ControlPlaneError.MountConflict;
                }
            }
            try normalized_paths.append(self.allocator, normalized);
        }

        var unchanged = project.mounts.items.len == mount_specs.len;
        if (unchanged) {
            for (project.mounts.items, 0..) |existing, idx| {
                const expected_path = normalized_paths.items[idx];
                const expected_export = mount_specs[idx].export_name;
                if (!std.mem.eql(u8, existing.mount_path, expected_path) or
                    !std.mem.eql(u8, existing.node_id, node_id) or
                    !std.mem.eql(u8, existing.export_name, expected_export))
                {
                    unchanged = false;
                    break;
                }
            }
        }
        if (unchanged) return;

        for (project.mounts.items) |*mount| mount.deinit(self.allocator);
        project.mounts.clearRetainingCapacity();
        for (mount_specs, 0..) |spec, idx| {
            try project.mounts.append(self.allocator, .{
                .mount_path = try self.allocator.dupe(u8, normalized_paths.items[idx]),
                .node_id = try self.allocator.dupe(u8, node_id),
                .export_name = try self.allocator.dupe(u8, spec.export_name),
            });
        }
        project.updated_at_ms = now_ms;
        self.mount_sets_total +%= 1;
        self.persistSnapshotBestEffortLocked();
    }

    fn isPrimaryAgent(self: *const ControlPlane, agent_id: []const u8) bool {
        return std.mem.eql(u8, agent_id, self.primary_agent_id);
    }

    pub fn deinit(self: *ControlPlane) void {
        self.clearState();

        if (self.store) |store| {
            store.close();
            self.allocator.destroy(store);
            self.store = null;
        }
    }

    fn clearState(self: *ControlPlane) void {
        var invite_it = self.invites.valueIterator();
        while (invite_it.next()) |invite| invite.deinit(self.allocator);
        self.invites.deinit(self.allocator);
        self.invites = .{};

        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| node.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.nodes = .{};

        var project_it = self.projects.valueIterator();
        while (project_it.next()) |project| project.deinit(self.allocator);
        self.projects.deinit(self.allocator);
        self.projects = .{};

        var active_it = self.active_project_by_agent.iterator();
        while (active_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.active_project_by_agent.deinit(self.allocator);
        self.active_project_by_agent = .{};

        self.invites_created_total = 0;
        self.invites_redeemed_total = 0;
        self.node_joins_total = 0;
        self.node_lease_refresh_total = 0;
        self.nodes_ensured_total = 0;
        self.node_deletes_total = 0;
        self.project_creates_total = 0;
        self.project_updates_total = 0;
        self.project_deletes_total = 0;
        self.mount_sets_total = 0;
        self.mount_removes_total = 0;
        self.project_token_rotates_total = 0;
        self.project_token_revokes_total = 0;
        self.project_activations_total = 0;
        self.lease_reap_nodes_total = 0;

        if (self.reconcile_last_error) |value| {
            self.allocator.free(value);
            self.reconcile_last_error = null;
        }
        for (self.reconcile_last_failed_ops.items) |op| self.allocator.free(op);
        self.reconcile_last_failed_ops.deinit(self.allocator);
        self.reconcile_last_failed_ops = .{};
        self.reconcile_state = .pending;
        self.reconcile_last_reconcile_ms = 0;
        self.reconcile_last_success_ms = 0;
        self.reconcile_queue_depth = 0;
        self.reconcile_failed_ops_total = 0;
        self.reconcile_cycles_total = 0;
        self.reconcile_requested_at_ms = 0;
    }

    pub fn createNodeInvite(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const expires_in_ms = getOptionalUnsigned(obj, "expires_in_ms", 30 * 60 * 1000) catch return ControlPlaneError.InvalidPayload;
        const now = std.time.milliTimestamp();

        const invite_id = try makeSequentialId(self.allocator, "invite", &self.next_invite_id);
        errdefer self.allocator.free(invite_id);
        const token = try makeToken(self.allocator, "inv");
        errdefer self.allocator.free(token);

        const invite = Invite{
            .id = invite_id,
            .token = token,
            .created_at_ms = now,
            .expires_at_ms = now + @as(i64, @intCast(expires_in_ms)),
            .redeemed = false,
        };
        try self.invites.put(self.allocator, invite.id, invite);
        self.invites_created_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        const escaped_id = try jsonEscape(self.allocator, invite.id);
        defer self.allocator.free(escaped_id);
        const escaped_token = try jsonEscape(self.allocator, invite.token);
        defer self.allocator.free(escaped_token);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"invite_id\":\"{s}\",\"invite_token\":\"{s}\",\"created_at_ms\":{d},\"expires_at_ms\":{d}}}",
            .{ escaped_id, escaped_token, invite.created_at_ms, invite.expires_at_ms },
        );
    }

    pub fn nodeJoin(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const invite_token = getRequiredString(obj, "invite_token") catch return ControlPlaneError.MissingField;
        const node_name_raw = getOptionalString(obj, "node_name");
        const fs_url_raw = getOptionalString(obj, "fs_url") orelse "";
        const lease_ttl_ms = getOptionalUnsigned(obj, "lease_ttl_ms", 15 * 60 * 1000) catch return ControlPlaneError.InvalidPayload;
        const now = std.time.milliTimestamp();
        if (node_name_raw) |name| try validateIdentifier(name, 128);
        if (fs_url_raw.len > 0) try validateFsUrl(fs_url_raw);

        var matched: ?*Invite = null;
        var invite_it = self.invites.valueIterator();
        while (invite_it.next()) |invite| {
            if (std.mem.eql(u8, invite.token, invite_token)) {
                matched = invite;
                break;
            }
        }
        const invite = matched orelse return ControlPlaneError.InviteNotFound;
        if (invite.redeemed) return ControlPlaneError.InviteRedeemed;
        if (invite.expires_at_ms <= now) return ControlPlaneError.InviteExpired;
        invite.redeemed = true;
        self.invites_redeemed_total +%= 1;

        const node_id = try makeSequentialId(self.allocator, "node", &self.next_node_id);
        errdefer self.allocator.free(node_id);
        const node_name = if (node_name_raw) |name|
            try self.allocator.dupe(u8, name)
        else
            try self.allocator.dupe(u8, node_id);
        errdefer self.allocator.free(node_name);
        const fs_url = try self.allocator.dupe(u8, fs_url_raw);
        errdefer self.allocator.free(fs_url);
        const node_secret = try makeToken(self.allocator, "secret");
        errdefer self.allocator.free(node_secret);
        const lease_token = try makeToken(self.allocator, "lease");
        errdefer self.allocator.free(lease_token);

        const node = Node{
            .id = node_id,
            .name = node_name,
            .fs_url = fs_url,
            .secret = node_secret,
            .lease_token = lease_token,
            .joined_at_ms = now,
            .last_seen_ms = now,
            .lease_expires_at_ms = now + @as(i64, @intCast(lease_ttl_ms)),
        };
        try self.nodes.put(self.allocator, node.id, node);
        self.node_joins_total +%= 1;
        self.persistSnapshotBestEffortLocked();
        std.log.info("control-plane node joined: id={s} name={s} fs_url={s}", .{ node.id, node.name, node.fs_url });

        return self.renderNodeJoinPayload(node.id);
    }

    pub fn refreshNodeLease(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const node_id = getRequiredString(obj, "node_id") catch return ControlPlaneError.MissingField;
        const node_secret = getRequiredString(obj, "node_secret") catch return ControlPlaneError.MissingField;
        const lease_ttl_ms = getOptionalUnsigned(obj, "lease_ttl_ms", 15 * 60 * 1000) catch return ControlPlaneError.InvalidPayload;
        try validateIdentifier(node_id, 128);
        try validateSecretToken(node_secret, 256);

        const node = self.nodes.getPtr(node_id) orelse return ControlPlaneError.NodeNotFound;
        if (!std.mem.eql(u8, node.secret, node_secret)) return ControlPlaneError.NodeAuthFailed;

        if (getOptionalString(obj, "fs_url")) |next_fs_url| {
            try validateFsUrl(next_fs_url);
            self.allocator.free(node.fs_url);
            node.fs_url = try self.allocator.dupe(u8, next_fs_url);
        }

        self.allocator.free(node.lease_token);
        node.lease_token = try makeToken(self.allocator, "lease");
        node.last_seen_ms = std.time.milliTimestamp();
        node.lease_expires_at_ms = node.last_seen_ms + @as(i64, @intCast(lease_ttl_ms));
        self.node_lease_refresh_total +%= 1;
        self.persistSnapshotBestEffortLocked();
        std.log.info("control-plane node lease refreshed: id={s} expires_at={d}", .{ node.id, node.lease_expires_at_ms });

        return self.renderNodeJoinPayload(node.id);
    }

    pub fn ensureNode(
        self: *ControlPlane,
        node_name: []const u8,
        fs_url: []const u8,
        lease_ttl_ms: u64,
    ) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        if (node_name.len == 0) return ControlPlaneError.InvalidPayload;
        try validateIdentifier(node_name, 128);
        try validateFsUrl(fs_url);

        const now = std.time.milliTimestamp();
        var existing_node: ?*Node = null;
        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| {
            if (!std.mem.eql(u8, node.name, node_name)) continue;
            existing_node = node;
            break;
        }

        if (existing_node) |node| {
            self.allocator.free(node.fs_url);
            node.fs_url = try self.allocator.dupe(u8, fs_url);

            self.allocator.free(node.lease_token);
            node.lease_token = try makeToken(self.allocator, "lease");
            node.last_seen_ms = now;
            node.lease_expires_at_ms = now + @as(i64, @intCast(lease_ttl_ms));
            self.nodes_ensured_total +%= 1;
            self.persistSnapshotBestEffortLocked();
            std.log.info("control-plane node ensured (existing): id={s} name={s} fs_url={s}", .{ node.id, node.name, node.fs_url });

            return self.renderNodeJoinPayload(node.id);
        }

        const node_id = try makeSequentialId(self.allocator, "node", &self.next_node_id);
        errdefer self.allocator.free(node_id);
        const node = Node{
            .id = node_id,
            .name = try self.allocator.dupe(u8, node_name),
            .fs_url = try self.allocator.dupe(u8, fs_url),
            .secret = try makeToken(self.allocator, "secret"),
            .lease_token = try makeToken(self.allocator, "lease"),
            .joined_at_ms = now,
            .last_seen_ms = now,
            .lease_expires_at_ms = now + @as(i64, @intCast(lease_ttl_ms)),
        };
        errdefer {
            self.allocator.free(node.name);
            self.allocator.free(node.fs_url);
            self.allocator.free(node.secret);
            self.allocator.free(node.lease_token);
        }
        try self.nodes.put(self.allocator, node.id, node);
        self.nodes_ensured_total +%= 1;
        self.persistSnapshotBestEffortLocked();
        std.log.info("control-plane node ensured (new): id={s} name={s} fs_url={s}", .{ node.id, node.name, node.fs_url });

        return self.renderNodeJoinPayload(node.id);
    }

    pub fn listNodes(self: *ControlPlane) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "{\"nodes\":[");
        var first = true;
        var it = self.nodes.valueIterator();
        while (it.next()) |node| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendNodeJson(self.allocator, &out, node.*);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    pub fn getNode(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const node_id = getRequiredString(obj, "node_id") catch return ControlPlaneError.MissingField;
        const node = self.nodes.get(node_id) orelse return ControlPlaneError.NodeNotFound;

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"node\":");
        try appendNodeJson(self.allocator, &out, node);
        try out.appendSlice(self.allocator, "}");
        return out.toOwnedSlice(self.allocator);
    }

    pub fn deleteNode(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const node_id = getRequiredString(obj, "node_id") catch return ControlPlaneError.MissingField;
        const node_secret = getRequiredString(obj, "node_secret") catch return ControlPlaneError.MissingField;
        try validateIdentifier(node_id, 128);
        try validateSecretToken(node_secret, 256);

        const node = self.nodes.get(node_id) orelse return ControlPlaneError.NodeNotFound;
        if (!std.mem.eql(u8, node.secret, node_secret)) return ControlPlaneError.NodeAuthFailed;

        try self.deleteNodeByIdLocked(node_id, std.time.milliTimestamp());

        const escaped_id = try jsonEscape(self.allocator, node_id);
        defer self.allocator.free(escaped_id);
        return std.fmt.allocPrint(self.allocator, "{{\"deleted\":true,\"node_id\":\"{s}\"}}", .{escaped_id});
    }

    pub fn unregisterNodeById(self: *ControlPlane, node_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());
        try self.deleteNodeByIdLocked(node_id, std.time.milliTimestamp());
    }

    pub fn createProject(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const name_raw = getRequiredString(obj, "name") catch return ControlPlaneError.MissingField;
        const vision_raw = getOptionalString(obj, "vision") orelse "";
        const status_raw = getOptionalString(obj, "status") orelse "active";
        const now = std.time.milliTimestamp();
        try validateDisplayString(name_raw, 128);
        try validateIdentifier(status_raw, 64);
        try validateDisplayStringAllowEmpty(vision_raw, 1024);

        const project_id = try makeSequentialId(self.allocator, "proj", &self.next_project_id);
        errdefer self.allocator.free(project_id);
        const mutation_token = try makeToken(self.allocator, "proj");
        errdefer self.allocator.free(mutation_token);

        const project = Project{
            .id = project_id,
            .name = try self.allocator.dupe(u8, name_raw),
            .vision = try self.allocator.dupe(u8, vision_raw),
            .status = try self.allocator.dupe(u8, status_raw),
            .mutation_token = mutation_token,
            .created_at_ms = now,
            .updated_at_ms = now,
        };
        errdefer {
            self.allocator.free(project.name);
            self.allocator.free(project.vision);
            self.allocator.free(project.status);
            self.allocator.free(project.mutation_token);
        }
        try self.projects.put(self.allocator, project.id, project);
        self.project_creates_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        return renderProjectPayload(self.allocator, self.projects.get(project_id).?, true);
    }

    pub fn updateProject(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        const project_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        try validateSecretToken(project_token, 256);
        const project = self.projects.getPtr(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
        const next_name = getOptionalString(obj, "name");
        const next_vision = getOptionalString(obj, "vision");
        const next_status = getOptionalString(obj, "status");
        if (project.kind == .spider_web_builtin and
            (next_name != null or next_vision != null or next_status != null))
        {
            return ControlPlaneError.ProjectProtected;
        }

        if (next_name) |value| {
            try validateDisplayString(value, 128);
            self.allocator.free(project.name);
            project.name = try self.allocator.dupe(u8, value);
        }
        if (next_vision) |value| {
            try validateDisplayStringAllowEmpty(value, 1024);
            self.allocator.free(project.vision);
            project.vision = try self.allocator.dupe(u8, value);
        }
        if (next_status) |value| {
            try validateIdentifier(value, 64);
            self.allocator.free(project.status);
            project.status = try self.allocator.dupe(u8, value);
        }
        project.updated_at_ms = std.time.milliTimestamp();
        self.project_updates_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        return renderProjectPayload(self.allocator, project.*, false);
    }

    pub fn deleteProject(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        const project_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        try validateSecretToken(project_token, 256);

        const existing_project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (existing_project.is_delete_protected) return ControlPlaneError.ProjectProtected;
        if (!secureTokenEql(existing_project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
        const removed = self.projects.fetchRemove(project_id) orelse return ControlPlaneError.ProjectNotFound;
        var project = removed.value;
        defer project.deinit(self.allocator);

        var active_it = self.active_project_by_agent.iterator();
        while (active_it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.*, project_id)) {
                self.allocator.free(entry.value_ptr.*);
                entry.value_ptr.* = try self.allocator.dupe(u8, "");
            }
        }
        self.project_deletes_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        const escaped = try jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped);
        return std.fmt.allocPrint(self.allocator, "{{\"deleted\":true,\"project_id\":\"{s}\"}}", .{escaped});
    }

    pub fn listProjects(self: *ControlPlane) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, "{\"projects\":[");
        var first = true;
        var it = self.projects.valueIterator();
        while (it.next()) |project| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendProjectSummaryJson(self.allocator, &out, project.*);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    pub fn getProject(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;

        return renderProjectPayload(self.allocator, project, false);
    }

    pub fn setProjectMount(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const project_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        const node_id = getRequiredString(obj, "node_id") catch return ControlPlaneError.MissingField;
        const export_name = getRequiredString(obj, "export_name") catch return ControlPlaneError.MissingField;
        const mount_path_raw = getRequiredString(obj, "mount_path") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        try validateSecretToken(project_token, 256);
        try validateIdentifier(node_id, 128);
        try validateExportName(export_name);

        if (!self.nodes.contains(node_id)) return ControlPlaneError.NodeNotFound;
        const project = self.projects.getPtr(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (project.kind == .spider_web_builtin) return ControlPlaneError.ProjectProtected;
        if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;

        const mount_path = try normalizeMountPath(self.allocator, mount_path_raw);
        errdefer self.allocator.free(mount_path);
        for (project.mounts.items) |existing| {
            if (std.mem.eql(u8, existing.mount_path, mount_path)) {
                if (std.mem.eql(u8, existing.node_id, node_id) and std.mem.eql(u8, existing.export_name, export_name)) {
                    self.allocator.free(mount_path);
                    return renderProjectPayload(self.allocator, project.*, false);
                }
                // Exact same mount path on different nodes is a failover group and is allowed.
                continue;
            }
            if (mountPathsOverlap(existing.mount_path, mount_path)) return ControlPlaneError.MountConflict;
        }

        try project.mounts.append(self.allocator, .{
            .mount_path = mount_path,
            .node_id = try self.allocator.dupe(u8, node_id),
            .export_name = try self.allocator.dupe(u8, export_name),
        });
        project.updated_at_ms = std.time.milliTimestamp();
        self.mount_sets_total +%= 1;
        self.persistSnapshotBestEffortLocked();
        std.log.info(
            "control-plane mount set: project={s} node={s} export={s} path={s}",
            .{ project_id, node_id, export_name, mount_path },
        );

        return renderProjectPayload(self.allocator, project.*, false);
    }

    pub fn removeProjectMount(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const project_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        const mount_path_raw = getRequiredString(obj, "mount_path") catch return ControlPlaneError.MissingField;
        const node_id_filter = getOptionalString(obj, "node_id");
        const export_name_filter = getOptionalString(obj, "export_name");
        try validateIdentifier(project_id, 128);
        try validateSecretToken(project_token, 256);
        if ((node_id_filter == null) != (export_name_filter == null)) return ControlPlaneError.MissingField;
        if (node_id_filter) |node_id| try validateIdentifier(node_id, 128);
        if (export_name_filter) |export_name| try validateExportName(export_name);
        const mount_path = try normalizeMountPath(self.allocator, mount_path_raw);
        defer self.allocator.free(mount_path);

        const project = self.projects.getPtr(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (project.kind == .spider_web_builtin) return ControlPlaneError.ProjectProtected;
        if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
        var removed_count: u32 = 0;
        var i: usize = 0;
        while (i < project.mounts.items.len) {
            const mount = project.mounts.items[i];
            if (!std.mem.eql(u8, mount.mount_path, mount_path)) {
                i += 1;
                continue;
            }
            if (node_id_filter) |node_id| {
                if (!std.mem.eql(u8, mount.node_id, node_id)) {
                    i += 1;
                    continue;
                }
                if (!std.mem.eql(u8, mount.export_name, export_name_filter.?)) {
                    i += 1;
                    continue;
                }
            }

            var removed = project.mounts.orderedRemove(i);
            removed.deinit(self.allocator);
            removed_count +%= 1;
            if (node_id_filter != null) break;
        }
        if (removed_count == 0) return ControlPlaneError.MountNotFound;
        project.updated_at_ms = std.time.milliTimestamp();
        self.mount_removes_total +%= removed_count;
        self.persistSnapshotBestEffortLocked();

        return renderProjectPayload(self.allocator, project.*, false);
    }

    pub fn listProjectMounts(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;

        const escaped_id = try jsonEscape(self.allocator, project.id);
        defer self.allocator.free(escaped_id);
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(self.allocator);
        try out.writer(self.allocator).print("{{\"project_id\":\"{s}\",\"mounts\":[", .{escaped_id});
        for (project.mounts.items, 0..) |mount, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            try appendMountJson(self.allocator, &out, mount);
        }
        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    pub fn rotateProjectToken(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const current_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        try validateSecretToken(current_token, 256);
        const project = self.projects.getPtr(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (project.kind == .spider_web_builtin) return ControlPlaneError.ProjectProtected;
        if (!secureTokenEql(project.mutation_token, current_token)) return ControlPlaneError.ProjectAuthFailed;

        self.allocator.free(project.mutation_token);
        project.mutation_token = try makeToken(self.allocator, "proj");
        project.updated_at_ms = std.time.milliTimestamp();
        self.project_token_rotates_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        const escaped_project = try jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_token = try jsonEscape(self.allocator, project.mutation_token);
        defer self.allocator.free(escaped_token);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"rotated\":true,\"updated_at_ms\":{d}}}",
            .{ escaped_project, escaped_token, project.updated_at_ms },
        );
    }

    pub fn revokeProjectToken(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.reapExpiredLeasesLocked(std.time.milliTimestamp());

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        const current_token = getRequiredString(obj, "project_token") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        try validateSecretToken(current_token, 256);
        const project = self.projects.getPtr(project_id) orelse return ControlPlaneError.ProjectNotFound;
        if (project.kind == .spider_web_builtin) return ControlPlaneError.ProjectProtected;
        if (!secureTokenEql(project.mutation_token, current_token)) return ControlPlaneError.ProjectAuthFailed;

        self.allocator.free(project.mutation_token);
        project.mutation_token = try makeToken(self.allocator, "proj");
        project.updated_at_ms = std.time.milliTimestamp();
        self.project_token_revokes_total +%= 1;
        self.persistSnapshotBestEffortLocked();

        const escaped_project = try jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_token = try jsonEscape(self.allocator, project.mutation_token);
        defer self.allocator.free(escaped_token);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"revoked\":true,\"updated_at_ms\":{d}}}",
            .{ escaped_project, escaped_token, project.updated_at_ms },
        );
    }

    pub fn activateProject(self: *ControlPlane, agent_id: []const u8, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;
        const project_id = getRequiredString(obj, "project_id") catch return ControlPlaneError.MissingField;
        try validateIdentifier(project_id, 128);
        const project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;
        const is_primary_agent = self.isPrimaryAgent(agent_id);
        if (project.kind == .spider_web_builtin and !is_primary_agent) return ControlPlaneError.ProjectAssignmentForbidden;

        const maybe_project_token = getOptionalString(obj, "project_token");
        if (!is_primary_agent) {
            const project_token = maybe_project_token orelse return ControlPlaneError.MissingField;
            try validateSecretToken(project_token, 256);
            if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
        } else if (maybe_project_token) |project_token| {
            try validateSecretToken(project_token, 256);
            if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
        }

        if (self.active_project_by_agent.getPtr(agent_id)) |existing| {
            self.allocator.free(existing.*);
            existing.* = try self.allocator.dupe(u8, project_id);
        } else {
            try self.active_project_by_agent.put(
                self.allocator,
                try self.allocator.dupe(u8, agent_id),
                try self.allocator.dupe(u8, project_id),
            );
        }
        self.project_activations_total +%= 1;
        if (project.kind == .spider_web_builtin and project.mounts.items.len == 0 and self.spider_web_root.len > 0) {
            std.log.info("spider-web project active without mount; waiting for local node registration (root={s})", .{self.spider_web_root});
        }
        self.persistSnapshotBestEffortLocked();

        const workspace_root = try std.fmt.allocPrint(self.allocator, "/spiderweb/projects/{s}/workspace", .{project_id});
        defer self.allocator.free(workspace_root);
        const escaped_agent = try jsonEscape(self.allocator, agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = try jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_root = try jsonEscape(self.allocator, workspace_root);
        defer self.allocator.free(escaped_root);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"workspace_root\":\"{s}\"}}",
            .{ escaped_agent, escaped_project, escaped_root },
        );
    }

    pub fn requestReconcile(self: *ControlPlane) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.requestReconcileLocked(std.time.milliTimestamp());
    }

    pub fn runReconcileCycle(self: *ControlPlane, force: bool) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        const ran = try self.runReconcileCycleLocked(now_ms, force);
        if (!ran) return null;
        return try self.buildReconcileStatusPayloadLocked(null, true);
    }

    pub fn reconcileStatus(self: *ControlPlane, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        _ = try self.runReconcileCycleLocked(now_ms, false);
        return try self.buildReconcileStatusPayloadLocked(payload_json, true);
    }

    pub fn projectUp(self: *ControlPlane, agent_id: []const u8, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);

        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        const obj = payload.value.object;

        const requested_project_id = getOptionalString(obj, "project_id");
        const requested_name = getOptionalString(obj, "name") orelse getOptionalString(obj, "project_name");
        const requested_vision = getOptionalString(obj, "vision");
        const requested_status = getOptionalString(obj, "status");
        const requested_project_token = getOptionalString(obj, "project_token");
        const activate = getOptionalBool(obj, "activate", true) catch return ControlPlaneError.InvalidPayload;
        if (requested_project_token) |project_token| try validateSecretToken(project_token, 256);

        var project_ptr: ?*Project = null;
        var created = false;
        var mounts_replaced = false;

        if (requested_project_id) |project_id| {
            try validateIdentifier(project_id, 128);
            project_ptr = self.projects.getPtr(project_id);
            if (project_ptr == null) return ControlPlaneError.ProjectNotFound;
        } else if (requested_name) |project_name| {
            try validateDisplayString(project_name, 128);
            var project_it = self.projects.valueIterator();
            while (project_it.next()) |project| {
                if (std.mem.eql(u8, project.name, project_name)) {
                    project_ptr = project;
                    break;
                }
            }
        }

        if (project_ptr == null) {
            const name_raw = requested_name orelse return ControlPlaneError.MissingField;
            const vision_raw = requested_vision orelse "";
            const status_raw = requested_status orelse "active";
            try validateDisplayString(name_raw, 128);
            try validateDisplayStringAllowEmpty(vision_raw, 1024);
            try validateIdentifier(status_raw, 64);

            const project_id = try makeSequentialId(self.allocator, "proj", &self.next_project_id);
            errdefer self.allocator.free(project_id);
            const mutation_token = try makeToken(self.allocator, "proj");
            errdefer self.allocator.free(mutation_token);

            const project = Project{
                .id = project_id,
                .name = try self.allocator.dupe(u8, name_raw),
                .vision = try self.allocator.dupe(u8, vision_raw),
                .status = try self.allocator.dupe(u8, status_raw),
                .mutation_token = mutation_token,
                .created_at_ms = now_ms,
                .updated_at_ms = now_ms,
            };
            errdefer {
                self.allocator.free(project.name);
                self.allocator.free(project.vision);
                self.allocator.free(project.status);
                self.allocator.free(project.mutation_token);
            }

            try self.projects.put(self.allocator, project.id, project);
            self.project_creates_total +%= 1;
            project_ptr = self.projects.getPtr(project_id).?;
            created = true;
        }

        const project = project_ptr.?;
        const is_primary_agent = self.isPrimaryAgent(agent_id);
        if (project.kind == .spider_web_builtin and !is_primary_agent) {
            return ControlPlaneError.ProjectAssignmentForbidden;
        }
        if (!created) {
            if (project.kind == .spider_web_builtin) {
                if (requested_project_token) |project_token| {
                    if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
                }
            } else {
                const project_token = requested_project_token orelse return ControlPlaneError.MissingField;
                if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
            }
            if (project.kind == .spider_web_builtin and
                (requested_name != null or requested_vision != null or requested_status != null or obj.get("desired_mounts") != null))
            {
                return ControlPlaneError.ProjectProtected;
            }
            if (requested_name) |next_name| {
                try validateDisplayString(next_name, 128);
                self.allocator.free(project.name);
                project.name = try self.allocator.dupe(u8, next_name);
            }
            if (requested_vision) |next_vision| {
                try validateDisplayStringAllowEmpty(next_vision, 1024);
                self.allocator.free(project.vision);
                project.vision = try self.allocator.dupe(u8, next_vision);
            }
            if (requested_status) |next_status| {
                try validateIdentifier(next_status, 64);
                self.allocator.free(project.status);
                project.status = try self.allocator.dupe(u8, next_status);
            }
        }

        if (obj.get("desired_mounts")) |desired_val| {
            if (project.kind == .spider_web_builtin) return ControlPlaneError.ProjectProtected;
            if (desired_val != .array) return ControlPlaneError.InvalidPayload;
            var next_mounts = std.ArrayListUnmanaged(ProjectMount){};
            errdefer {
                for (next_mounts.items) |*mount| mount.deinit(self.allocator);
                next_mounts.deinit(self.allocator);
            }

            for (desired_val.array.items) |item| {
                if (item != .object) return ControlPlaneError.InvalidPayload;
                const mount_obj = item.object;
                const node_id = getRequiredString(mount_obj, "node_id") catch return ControlPlaneError.MissingField;
                const export_name = getRequiredString(mount_obj, "export_name") catch return ControlPlaneError.MissingField;
                const mount_path_raw = getRequiredString(mount_obj, "mount_path") catch return ControlPlaneError.MissingField;
                try validateIdentifier(node_id, 128);
                try validateExportName(export_name);
                if (!self.nodes.contains(node_id)) return ControlPlaneError.NodeNotFound;
                const mount_path = try normalizeMountPath(self.allocator, mount_path_raw);
                errdefer self.allocator.free(mount_path);

                var duplicate_exact = false;
                for (next_mounts.items) |existing| {
                    if (std.mem.eql(u8, existing.mount_path, mount_path)) {
                        if (std.mem.eql(u8, existing.node_id, node_id) and std.mem.eql(u8, existing.export_name, export_name)) {
                            duplicate_exact = true;
                            break;
                        }
                        continue;
                    }
                    if (mountPathsOverlap(existing.mount_path, mount_path)) return ControlPlaneError.MountConflict;
                }
                if (duplicate_exact) {
                    self.allocator.free(mount_path);
                    continue;
                }

                try next_mounts.append(self.allocator, .{
                    .mount_path = mount_path,
                    .node_id = try self.allocator.dupe(u8, node_id),
                    .export_name = try self.allocator.dupe(u8, export_name),
                });
            }

            for (project.mounts.items) |*mount| mount.deinit(self.allocator);
            project.mounts.deinit(self.allocator);
            project.mounts = next_mounts;
            mounts_replaced = true;
        }

        project.updated_at_ms = now_ms;
        if (!created) self.project_updates_total +%= 1;
        if (mounts_replaced) self.mount_sets_total +%= 1;

        if (activate) {
            if (project.kind == .spider_web_builtin and !is_primary_agent) {
                return ControlPlaneError.ProjectAssignmentForbidden;
            }
            if (self.active_project_by_agent.getPtr(agent_id)) |existing| {
                self.allocator.free(existing.*);
                existing.* = try self.allocator.dupe(u8, project.id);
            } else {
                try self.active_project_by_agent.put(
                    self.allocator,
                    try self.allocator.dupe(u8, agent_id),
                    try self.allocator.dupe(u8, project.id),
                );
            }
            self.project_activations_total +%= 1;
        }

        self.requestReconcileLocked(now_ms);
        _ = try self.runReconcileCycleLocked(now_ms, false);
        self.persistSnapshotBestEffortLocked();

        const workspace_json = try self.renderWorkspaceStatusForProjectLocked(agent_id, project.id, now_ms);
        defer self.allocator.free(workspace_json);
        const escaped_project = try jsonEscape(self.allocator, project.id);
        defer self.allocator.free(escaped_project);
        const escaped_token = try jsonEscape(self.allocator, project.mutation_token);
        defer self.allocator.free(escaped_token);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"created\":{s},\"activated\":{s},\"workspace\":{s}}}",
            .{
                escaped_project,
                escaped_token,
                if (created) "true" else "false",
                if (activate) "true" else "false",
                workspace_json,
            },
        );
    }

    pub fn workspaceStatus(self: *ControlPlane, agent_id: []const u8, payload_json: ?[]const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        _ = try self.runReconcileCycleLocked(now_ms, false);

        var selected_project_id: ?[]const u8 = null;
        var selected_project_token: ?[]const u8 = null;
        var payload = try parsePayload(self.allocator, payload_json);
        defer payload.deinit();
        if (getOptionalString(payload.value.object, "project_id")) |project_id| {
            try validateIdentifier(project_id, 128);
            selected_project_id = project_id;
        }
        if (getOptionalString(payload.value.object, "project_token")) |project_token| {
            try validateSecretToken(project_token, 256);
            selected_project_token = project_token;
        }

        const escaped_agent = try jsonEscape(self.allocator, agent_id);
        defer self.allocator.free(escaped_agent);
        if (selected_project_id) |project_id| {
            const project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;
            const is_primary_agent = self.isPrimaryAgent(agent_id);
            if (project.kind == .spider_web_builtin and !is_primary_agent) {
                return ControlPlaneError.ProjectAssignmentForbidden;
            }
            if (selected_project_token) |project_token| {
                if (!secureTokenEql(project.mutation_token, project_token)) return ControlPlaneError.ProjectAuthFailed;
            } else if (self.active_project_by_agent.get(agent_id)) |active_project_id| {
                if (!std.mem.eql(u8, active_project_id, project_id)) return ControlPlaneError.ProjectAuthFailed;
            } else if (is_primary_agent) {
                // Primary agent can inspect any project without an explicit token.
            } else {
                return ControlPlaneError.ProjectAuthFailed;
            }
            return try self.renderWorkspaceStatusForProjectLocked(agent_id, project_id, now_ms);
        }
        if (self.active_project_by_agent.get(agent_id)) |active_project_id| {
            if (active_project_id.len > 0) {
                if (self.projects.get(active_project_id)) |active_project| {
                    if (active_project.kind == .spider_web_builtin and !self.isPrimaryAgent(agent_id)) {
                        self.allocator.free(self.active_project_by_agent.getPtr(agent_id).?.*);
                        self.active_project_by_agent.getPtr(agent_id).?.* = try self.allocator.dupe(u8, "");
                        self.persistSnapshotBestEffortLocked();
                    } else {
                        return try self.renderWorkspaceStatusForProjectLocked(agent_id, active_project_id, now_ms);
                    }
                }
            }
        }

        const last_error_json = if (self.reconcile_last_error) |value| blk: {
            const escaped = try jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(last_error_json);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"agent_id\":\"{s}\",\"project_id\":null,\"workspace_root\":null,\"mounts\":[],\"desired_mounts\":[],\"actual_mounts\":[],\"drift\":{{\"count\":0,\"items\":[]}},\"reconcile_state\":\"{s}\",\"last_reconcile_ms\":{d},\"last_success_ms\":{d},\"last_error\":{s},\"queue_depth\":{d}}}",
            .{
                escaped_agent,
                reconcileStateName(self.reconcile_state),
                self.reconcile_last_reconcile_ms,
                self.reconcile_last_success_ms,
                last_error_json,
                self.reconcile_queue_depth,
            },
        );
    }

    fn requestReconcileLocked(self: *ControlPlane, now_ms: i64) void {
        self.reconcile_requested_at_ms = now_ms;
        if (self.reconcile_state == .idle) self.reconcile_state = .pending;
    }

    fn clearReconcileFailureListLocked(self: *ControlPlane) void {
        for (self.reconcile_last_failed_ops.items) |value| self.allocator.free(value);
        self.reconcile_last_failed_ops.clearRetainingCapacity();
    }

    fn setReconcileLastErrorLocked(self: *ControlPlane, message: ?[]const u8) !void {
        if (self.reconcile_last_error) |value| {
            self.allocator.free(value);
            self.reconcile_last_error = null;
        }
        if (message) |value| {
            const copied = try self.allocator.dupe(u8, value);
            self.reconcile_last_error = copied;
        }
    }

    fn runReconcileCycleLocked(self: *ControlPlane, now_ms: i64, force: bool) !bool {
        const periodic_interval_ms: i64 = 5_000;
        if (!force) {
            if (self.reconcile_requested_at_ms != 0) {
                if (now_ms - self.reconcile_requested_at_ms < self.reconcile_debounce_ms) return false;
            } else if (self.reconcile_last_reconcile_ms != 0) {
                if (now_ms - self.reconcile_last_reconcile_ms < periodic_interval_ms) return false;
            }
        }

        self.reconcile_state = .running;
        self.reconcile_cycles_total +%= 1;

        var new_failed_ops = std.ArrayListUnmanaged([]u8){};
        var adopted_failed_ops = false;
        defer if (!adopted_failed_ops) {
            for (new_failed_ops.items) |value| self.allocator.free(value);
            new_failed_ops.deinit(self.allocator);
        };

        var queue_depth: u32 = 0;
        var project_it = self.projects.valueIterator();
        while (project_it.next()) |project| {
            var summary = try self.evaluateProjectDriftLocked(project.*, now_ms, null);
            var attempt: u32 = 0;
            while (summary.queue_depth > 0 and attempt + 1 < self.reconcile_max_retries_per_cycle) : (attempt += 1) {
                _ = self.reconcile_retry_backoff_ms;
                summary = try self.evaluateProjectDriftLocked(project.*, now_ms, null);
            }
            if (summary.queue_depth > 0) {
                const final_summary = try self.evaluateProjectDriftLocked(project.*, now_ms, &new_failed_ops);
                queue_depth +%= final_summary.queue_depth;
            }
        }

        self.clearReconcileFailureListLocked();
        self.reconcile_last_failed_ops = new_failed_ops;
        adopted_failed_ops = true;

        self.reconcile_queue_depth = queue_depth;
        self.reconcile_last_reconcile_ms = now_ms;
        self.reconcile_requested_at_ms = 0;

        if (queue_depth == 0 and self.reconcile_last_failed_ops.items.len == 0) {
            self.reconcile_state = .idle;
            self.reconcile_last_success_ms = now_ms;
            try self.setReconcileLastErrorLocked(null);
        } else {
            self.reconcile_state = .degraded;
            self.reconcile_failed_ops_total +%= @as(u64, @intCast(self.reconcile_last_failed_ops.items.len));
            if (self.reconcile_last_failed_ops.items.len > 0) {
                try self.setReconcileLastErrorLocked(self.reconcile_last_failed_ops.items[0]);
            } else {
                try self.setReconcileLastErrorLocked("reconcile queue is non-empty");
            }
        }

        return true;
    }

    fn buildReconcileStatusPayloadLocked(
        self: *ControlPlane,
        payload_json: ?[]const u8,
        include_projects: bool,
    ) ![]u8 {
        var selected_project_id: ?[]const u8 = null;
        if (payload_json != null) {
            var payload = try parsePayload(self.allocator, payload_json);
            defer payload.deinit();
            if (getOptionalString(payload.value.object, "project_id")) |project_id| {
                try validateIdentifier(project_id, 128);
                if (!self.projects.contains(project_id)) return ControlPlaneError.ProjectNotFound;
                selected_project_id = project_id;
            }
        }

        const last_error_json = if (self.reconcile_last_error) |value| blk: {
            const escaped = try jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(last_error_json);

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.writer(self.allocator).print(
            "{{\"reconcile_state\":\"{s}\",\"last_reconcile_ms\":{d},\"last_success_ms\":{d},\"last_error\":{s},\"queue_depth\":{d},\"failed_ops_total\":{d},\"cycles_total\":{d},\"failed_ops\":[",
            .{
                reconcileStateName(self.reconcile_state),
                self.reconcile_last_reconcile_ms,
                self.reconcile_last_success_ms,
                last_error_json,
                self.reconcile_queue_depth,
                self.reconcile_failed_ops_total,
                self.reconcile_cycles_total,
            },
        );
        for (self.reconcile_last_failed_ops.items, 0..) |message, idx| {
            if (idx != 0) try out.append(self.allocator, ',');
            const escaped = try jsonEscape(self.allocator, message);
            defer self.allocator.free(escaped);
            try out.writer(self.allocator).print("\"{s}\"", .{escaped});
        }
        try out.appendSlice(self.allocator, "]");

        if (include_projects) {
            const now_ms = std.time.milliTimestamp();
            try out.appendSlice(self.allocator, ",\"projects\":[");
            var first = true;
            var project_it = self.projects.valueIterator();
            while (project_it.next()) |project| {
                if (selected_project_id) |selected| {
                    if (!std.mem.eql(u8, selected, project.id)) continue;
                }
                const summary = try self.evaluateProjectDriftLocked(project.*, now_ms, null);
                if (!first) try out.append(self.allocator, ',');
                first = false;
                const escaped_project = try jsonEscape(self.allocator, project.id);
                defer self.allocator.free(escaped_project);
                try out.writer(self.allocator).print(
                    "{{\"project_id\":\"{s}\",\"mounts\":{d},\"drift_count\":{d},\"queue_depth\":{d}}}",
                    .{
                        escaped_project,
                        project.mounts.items.len,
                        summary.drift_count,
                        summary.queue_depth,
                    },
                );
            }
            try out.appendSlice(self.allocator, "]");
        }

        try out.appendSlice(self.allocator, "}");
        return out.toOwnedSlice(self.allocator);
    }

    fn renderWorkspaceStatusForProjectLocked(
        self: *ControlPlane,
        agent_id: []const u8,
        project_id: []const u8,
        now_ms: i64,
    ) ![]u8 {
        const project = self.projects.get(project_id) orelse return ControlPlaneError.ProjectNotFound;
        const workspace_root = try std.fmt.allocPrint(self.allocator, "/spiderweb/projects/{s}/workspace", .{project_id});
        defer self.allocator.free(workspace_root);
        const escaped_agent = try jsonEscape(self.allocator, agent_id);
        defer self.allocator.free(escaped_agent);
        const escaped_project = try jsonEscape(self.allocator, project_id);
        defer self.allocator.free(escaped_project);
        const escaped_root = try jsonEscape(self.allocator, workspace_root);
        defer self.allocator.free(escaped_root);
        const last_error_json = if (self.reconcile_last_error) |value| blk: {
            const escaped = try jsonEscape(self.allocator, value);
            defer self.allocator.free(escaped);
            break :blk try std.fmt.allocPrint(self.allocator, "\"{s}\"", .{escaped});
        } else try self.allocator.dupe(u8, "null");
        defer self.allocator.free(last_error_json);

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);
        try out.writer(self.allocator).print(
            "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\",\"workspace_root\":\"{s}\"",
            .{ escaped_agent, escaped_project, escaped_root },
        );
        const topology = try self.appendWorkspaceTopologyJsonLocked(&out, project, now_ms, null);
        try out.writer(self.allocator).print(
            ",\"reconcile_state\":\"{s}\",\"last_reconcile_ms\":{d},\"last_success_ms\":{d},\"last_error\":{s},\"queue_depth\":{d}}}",
            .{
                reconcileStateName(self.reconcile_state),
                self.reconcile_last_reconcile_ms,
                self.reconcile_last_success_ms,
                last_error_json,
                topology.queue_depth,
            },
        );
        return out.toOwnedSlice(self.allocator);
    }

    fn appendWorkspaceTopologyJsonLocked(
        self: *ControlPlane,
        out: *std.ArrayListUnmanaged(u8),
        project: Project,
        now_ms: i64,
        failed_ops: ?*std.ArrayListUnmanaged([]u8),
    ) !ReconcileProjectSummary {
        var first_by_path = std.StringHashMapUnmanaged(usize){};
        defer first_by_path.deinit(self.allocator);
        var selected_by_path = std.StringHashMapUnmanaged(usize){};
        defer selected_by_path.deinit(self.allocator);

        for (project.mounts.items, 0..) |mount, idx| {
            if (!first_by_path.contains(mount.mount_path)) {
                try first_by_path.put(self.allocator, mount.mount_path, idx);
            }
            if (selected_by_path.getPtr(mount.mount_path)) |selected_idx| {
                if (self.shouldSelectCandidateMountLocked(project, selected_idx.*, idx, now_ms)) {
                    selected_idx.* = idx;
                }
            } else {
                try selected_by_path.put(self.allocator, mount.mount_path, idx);
            }
        }

        try out.appendSlice(self.allocator, ",\"mounts\":[");
        var first = true;
        for (project.mounts.items, 0..) |mount, idx| {
            const selected_idx = selected_by_path.get(mount.mount_path) orelse continue;
            if (selected_idx != idx) continue;
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendWorkspaceMountJson(self.allocator, out, mount, self.nodes.get(mount.node_id));
        }
        try out.appendSlice(self.allocator, "],\"desired_mounts\":[");

        first = true;
        for (project.mounts.items) |mount| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendWorkspaceMountJson(self.allocator, out, mount, self.nodes.get(mount.node_id));
        }
        try out.appendSlice(self.allocator, "],\"actual_mounts\":[");

        first = true;
        for (project.mounts.items, 0..) |mount, idx| {
            const selected_idx = selected_by_path.get(mount.mount_path) orelse continue;
            if (selected_idx != idx) continue;
            if (!first) try out.append(self.allocator, ',');
            first = false;
            try appendWorkspaceMountJson(self.allocator, out, mount, self.nodes.get(mount.node_id));
        }
        try out.appendSlice(self.allocator, "],\"drift\":{\"count\":");

        var drift_items = std.ArrayListUnmanaged(u8){};
        defer drift_items.deinit(self.allocator);
        var summary = ReconcileProjectSummary{};
        var first_drift = true;
        for (project.mounts.items, 0..) |mount, idx| {
            const first_idx = first_by_path.get(mount.mount_path) orelse continue;
            if (first_idx != idx) continue;

            const selected_idx = selected_by_path.get(mount.mount_path) orelse continue;
            const selected_mount = project.mounts.items[selected_idx];
            const selected_node = self.nodes.get(selected_mount.node_id);
            const selected_online = if (selected_node) |resolved| resolved.lease_expires_at_ms > now_ms else false;

            if (selected_node == null) {
                summary.drift_count +%= 1;
                summary.queue_depth +%= 1;
                if (!first_drift) try drift_items.append(self.allocator, ',');
                first_drift = false;
                try appendDriftEntryJson(
                    self.allocator,
                    &drift_items,
                    selected_mount.mount_path,
                    "missing_node",
                    .err,
                    selected_mount.node_id,
                    mount.node_id,
                    "selected node is missing",
                );
                if (failed_ops) |ops| {
                    const message = try std.fmt.allocPrint(
                        self.allocator,
                        "project={s} mount={s} node={s} missing",
                        .{ project.id, selected_mount.mount_path, selected_mount.node_id },
                    );
                    try ops.append(self.allocator, message);
                }
                continue;
            }

            if (!selected_online) {
                summary.drift_count +%= 1;
                summary.queue_depth +%= 1;
                if (!first_drift) try drift_items.append(self.allocator, ',');
                first_drift = false;
                try appendDriftEntryJson(
                    self.allocator,
                    &drift_items,
                    selected_mount.mount_path,
                    "node_offline",
                    .err,
                    selected_mount.node_id,
                    mount.node_id,
                    "selected node lease is expired",
                );
                if (failed_ops) |ops| {
                    const message = try std.fmt.allocPrint(
                        self.allocator,
                        "project={s} mount={s} node={s} offline",
                        .{ project.id, selected_mount.mount_path, selected_mount.node_id },
                    );
                    try ops.append(self.allocator, message);
                }
                continue;
            }

            if (selected_idx != first_idx) {
                summary.drift_count +%= 1;
                if (!first_drift) try drift_items.append(self.allocator, ',');
                first_drift = false;
                try appendDriftEntryJson(
                    self.allocator,
                    &drift_items,
                    selected_mount.mount_path,
                    "failover_active",
                    .warning,
                    selected_mount.node_id,
                    mount.node_id,
                    "using healthy failover node",
                );
            }
        }

        try out.writer(self.allocator).print("{d},\"items\":[{s}]}}", .{ summary.drift_count, drift_items.items });
        return summary;
    }

    fn shouldSelectCandidateMountLocked(
        self: *ControlPlane,
        project: Project,
        current_idx: usize,
        candidate_idx: usize,
        now_ms: i64,
    ) bool {
        const current_mount = project.mounts.items[current_idx];
        const candidate_mount = project.mounts.items[candidate_idx];
        const current_node = self.nodes.get(current_mount.node_id);
        const candidate_node = self.nodes.get(candidate_mount.node_id);
        const current_online = if (current_node) |value| value.lease_expires_at_ms > now_ms else false;
        const candidate_online = if (candidate_node) |value| value.lease_expires_at_ms > now_ms else false;
        if (candidate_online and !current_online) return true;
        if (!candidate_online and current_online) return false;
        if (candidate_online and current_online) {
            return candidate_node.?.lease_expires_at_ms > current_node.?.lease_expires_at_ms;
        }
        return false;
    }

    fn evaluateProjectDriftLocked(
        self: *ControlPlane,
        project: Project,
        now_ms: i64,
        failed_ops: ?*std.ArrayListUnmanaged([]u8),
    ) !ReconcileProjectSummary {
        var scratch = std.ArrayListUnmanaged(u8){};
        defer scratch.deinit(self.allocator);
        return try self.appendWorkspaceTopologyJsonLocked(
            &scratch,
            project,
            now_ms,
            failed_ops,
        );
    }

    pub fn metricsJson(self: *ControlPlane) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        const snapshot = self.collectMetricsLocked(now_ms);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"invites\":{{\"active\":{d},\"created_total\":{d},\"redeemed_total\":{d}}},\"nodes\":{{\"online\":{d},\"total\":{d},\"joins_total\":{d},\"lease_refresh_total\":{d},\"ensured_total\":{d},\"deletes_total\":{d},\"reaped_total\":{d}}},\"projects\":{{\"total\":{d},\"active_bindings\":{d},\"creates_total\":{d},\"updates_total\":{d},\"deletes_total\":{d},\"token_rotates_total\":{d},\"token_revokes_total\":{d},\"activations_total\":{d},\"mounts_total\":{d},\"mount_sets_total\":{d},\"mount_removes_total\":{d}}}}}",
            .{
                snapshot.invites_active,
                self.invites_created_total,
                self.invites_redeemed_total,
                snapshot.nodes_online,
                snapshot.nodes_total,
                self.node_joins_total,
                self.node_lease_refresh_total,
                self.nodes_ensured_total,
                self.node_deletes_total,
                self.lease_reap_nodes_total,
                snapshot.projects_total,
                snapshot.active_project_bindings,
                self.project_creates_total,
                self.project_updates_total,
                self.project_deletes_total,
                self.project_token_rotates_total,
                self.project_token_revokes_total,
                self.project_activations_total,
                snapshot.mounts_total,
                self.mount_sets_total,
                self.mount_removes_total,
            },
        );
    }

    pub fn metricsPrometheus(self: *ControlPlane) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now_ms = std.time.milliTimestamp();
        _ = self.reapExpiredLeasesLocked(now_ms);
        const snapshot = self.collectMetricsLocked(now_ms);

        return std.fmt.allocPrint(
            self.allocator,
            \\# TYPE spiderweb_invites_active gauge
            \\spiderweb_invites_active {d}
            \\# TYPE spiderweb_invites_created_total counter
            \\spiderweb_invites_created_total {d}
            \\# TYPE spiderweb_invites_redeemed_total counter
            \\spiderweb_invites_redeemed_total {d}
            \\# TYPE spiderweb_nodes_online gauge
            \\spiderweb_nodes_online {d}
            \\# TYPE spiderweb_nodes_total gauge
            \\spiderweb_nodes_total {d}
            \\# TYPE spiderweb_node_joins_total counter
            \\spiderweb_node_joins_total {d}
            \\# TYPE spiderweb_node_lease_refresh_total counter
            \\spiderweb_node_lease_refresh_total {d}
            \\# TYPE spiderweb_nodes_ensured_total counter
            \\spiderweb_nodes_ensured_total {d}
            \\# TYPE spiderweb_node_deletes_total counter
            \\spiderweb_node_deletes_total {d}
            \\# TYPE spiderweb_lease_reap_nodes_total counter
            \\spiderweb_lease_reap_nodes_total {d}
            \\# TYPE spiderweb_projects_total gauge
            \\spiderweb_projects_total {d}
            \\# TYPE spiderweb_active_project_bindings gauge
            \\spiderweb_active_project_bindings {d}
            \\# TYPE spiderweb_project_creates_total counter
            \\spiderweb_project_creates_total {d}
            \\# TYPE spiderweb_project_updates_total counter
            \\spiderweb_project_updates_total {d}
            \\# TYPE spiderweb_project_deletes_total counter
            \\spiderweb_project_deletes_total {d}
            \\# TYPE spiderweb_project_token_rotates_total counter
            \\spiderweb_project_token_rotates_total {d}
            \\# TYPE spiderweb_project_token_revokes_total counter
            \\spiderweb_project_token_revokes_total {d}
            \\# TYPE spiderweb_project_activations_total counter
            \\spiderweb_project_activations_total {d}
            \\# TYPE spiderweb_project_mounts_total gauge
            \\spiderweb_project_mounts_total {d}
            \\# TYPE spiderweb_mount_sets_total counter
            \\spiderweb_mount_sets_total {d}
            \\# TYPE spiderweb_mount_removes_total counter
            \\spiderweb_mount_removes_total {d}
            \\
        ,
            .{
                snapshot.invites_active,
                self.invites_created_total,
                self.invites_redeemed_total,
                snapshot.nodes_online,
                snapshot.nodes_total,
                self.node_joins_total,
                self.node_lease_refresh_total,
                self.nodes_ensured_total,
                self.node_deletes_total,
                self.lease_reap_nodes_total,
                snapshot.projects_total,
                snapshot.active_project_bindings,
                self.project_creates_total,
                self.project_updates_total,
                self.project_deletes_total,
                self.project_token_rotates_total,
                self.project_token_revokes_total,
                self.project_activations_total,
                snapshot.mounts_total,
                self.mount_sets_total,
                self.mount_removes_total,
            },
        );
    }

    const MetricsSnapshot = struct {
        invites_active: usize,
        nodes_online: usize,
        nodes_total: usize,
        projects_total: usize,
        active_project_bindings: usize,
        mounts_total: usize,
    };

    fn collectMetricsLocked(self: *ControlPlane, now_ms: i64) MetricsSnapshot {
        var online_nodes: usize = 0;
        var mounts_total: usize = 0;

        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| {
            if (node.lease_expires_at_ms > now_ms) online_nodes += 1;
        }

        var project_it = self.projects.valueIterator();
        while (project_it.next()) |project| {
            mounts_total += project.mounts.items.len;
        }

        return .{
            .invites_active = self.invites.count(),
            .nodes_online = online_nodes,
            .nodes_total = self.nodes.count(),
            .projects_total = self.projects.count(),
            .active_project_bindings = self.active_project_by_agent.count(),
            .mounts_total = mounts_total,
        };
    }

    fn reapExpiredLeasesLocked(self: *ControlPlane, now_ms: i64) bool {
        var removed_any = false;
        var removed_count: u64 = 0;

        while (true) {
            var expired_id: ?[]const u8 = null;
            var node_it = self.nodes.valueIterator();
            while (node_it.next()) |node| {
                if (node.lease_expires_at_ms <= now_ms) {
                    expired_id = node.id;
                    break;
                }
            }
            const node_id = expired_id orelse break;

            const removed = self.nodes.fetchRemove(node_id) orelse continue;
            var node = removed.value;
            _ = self.dropNodeMountsFromProjectsLocked(node.id, now_ms);
            node.deinit(self.allocator);
            removed_any = true;
            removed_count += 1;
        }

        if (removed_any) self.persistSnapshotBestEffortLocked();
        if (removed_count > 0) {
            self.lease_reap_nodes_total +%= removed_count;
            std.log.info("control-plane lease reaper removed {d} expired nodes", .{removed_count});
        }
        return removed_any;
    }

    fn dropNodeMountsFromProjectsLocked(self: *ControlPlane, node_id: []const u8, now_ms: i64) bool {
        var changed_any = false;
        var project_it = self.projects.valueIterator();
        while (project_it.next()) |project| {
            var changed = false;
            var i: usize = 0;
            while (i < project.mounts.items.len) {
                if (std.mem.eql(u8, project.mounts.items[i].node_id, node_id)) {
                    var removed_mount = project.mounts.orderedRemove(i);
                    removed_mount.deinit(self.allocator);
                    changed = true;
                } else {
                    i += 1;
                }
            }
            if (changed) {
                changed_any = true;
                project.updated_at_ms = now_ms;
            }
        }
        return changed_any;
    }

    fn deleteNodeByIdLocked(self: *ControlPlane, node_id: []const u8, now_ms: i64) !void {
        const removed = self.nodes.fetchRemove(node_id) orelse return ControlPlaneError.NodeNotFound;
        var node = removed.value;
        defer node.deinit(self.allocator);

        _ = self.dropNodeMountsFromProjectsLocked(node_id, now_ms);
        self.node_deletes_total +%= 1;
        self.persistSnapshotBestEffortLocked();
        std.log.info("control-plane node deleted: {s}", .{node_id});
    }

    fn renderNodeJoinPayload(self: *ControlPlane, node_id: []const u8) ![]u8 {
        const node = self.nodes.get(node_id) orelse return ControlPlaneError.NodeNotFound;
        const escaped_id = try jsonEscape(self.allocator, node.id);
        defer self.allocator.free(escaped_id);
        const escaped_name = try jsonEscape(self.allocator, node.name);
        defer self.allocator.free(escaped_name);
        const escaped_url = try jsonEscape(self.allocator, node.fs_url);
        defer self.allocator.free(escaped_url);
        const escaped_secret = try jsonEscape(self.allocator, node.secret);
        defer self.allocator.free(escaped_secret);
        const escaped_lease = try jsonEscape(self.allocator, node.lease_token);
        defer self.allocator.free(escaped_lease);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"node_id\":\"{s}\",\"node_name\":\"{s}\",\"fs_url\":\"{s}\",\"node_secret\":\"{s}\",\"lease_token\":\"{s}\",\"lease_expires_at_ms\":{d}}}",
            .{ escaped_id, escaped_name, escaped_url, escaped_secret, escaped_lease, node.lease_expires_at_ms },
        );
    }

    fn persistSnapshotBestEffortLocked(self: *ControlPlane) void {
        self.requestReconcileLocked(std.time.milliTimestamp());
        self.persistSnapshotLocked() catch |err| {
            std.log.warn("control-plane snapshot persist failed: {s}", .{@errorName(err)});
        };
    }

    fn persistSnapshotLocked(self: *ControlPlane) !void {
        const store = self.store orelse return;

        const snapshot_json = try self.buildSnapshotJsonLocked();
        defer self.allocator.free(snapshot_json);
        const persisted_json = if (self.state_encryption_key) |key|
            try encryptSnapshotJson(self.allocator, snapshot_json, key)
        else
            try self.allocator.dupe(u8, snapshot_json);
        defer self.allocator.free(persisted_json);

        // Keep a single latest snapshot blob; historical versions are not needed.
        try store.deleteBaseId(persistence_base_id);
        try store.persistVersion(persistence_base_id, 1, persistence_kind, persisted_json);
    }

    fn loadSnapshotLocked(self: *ControlPlane) !void {
        const store = self.store orelse return;
        var record = (try store.load(self.allocator, persistence_base_id, null)) orelse return;
        defer record.deinit(self.allocator);

        if (!std.mem.eql(u8, record.kind, persistence_kind)) {
            std.log.warn(
                "control-plane snapshot kind mismatch: expected {s}, got {s}",
                .{ persistence_kind, record.kind },
            );
        }
        if (isEncryptedSnapshotEnvelope(record.content_json)) {
            const key = self.state_encryption_key orelse return error.MissingSnapshotEncryptionKey;
            const snapshot_json = try decryptSnapshotJson(self.allocator, record.content_json, key);
            defer self.allocator.free(snapshot_json);
            try self.restoreSnapshotFromJsonLocked(snapshot_json);
            return;
        }
        try self.restoreSnapshotFromJsonLocked(record.content_json);
    }

    fn buildSnapshotJsonLocked(self: *ControlPlane) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        try out.writer(self.allocator).print(
            "{{\"schema\":1,\"next\":{{\"invite_id\":{d},\"node_id\":{d},\"project_id\":{d}}},\"metrics\":{{\"invites_created_total\":{d},\"invites_redeemed_total\":{d},\"node_joins_total\":{d},\"node_lease_refresh_total\":{d},\"nodes_ensured_total\":{d},\"node_deletes_total\":{d},\"project_creates_total\":{d},\"project_updates_total\":{d},\"project_deletes_total\":{d},\"project_token_rotates_total\":{d},\"project_token_revokes_total\":{d},\"mount_sets_total\":{d},\"mount_removes_total\":{d},\"project_activations_total\":{d},\"lease_reap_nodes_total\":{d}}},\"invites\":[",
            .{
                self.next_invite_id,
                self.next_node_id,
                self.next_project_id,
                self.invites_created_total,
                self.invites_redeemed_total,
                self.node_joins_total,
                self.node_lease_refresh_total,
                self.nodes_ensured_total,
                self.node_deletes_total,
                self.project_creates_total,
                self.project_updates_total,
                self.project_deletes_total,
                self.project_token_rotates_total,
                self.project_token_revokes_total,
                self.mount_sets_total,
                self.mount_removes_total,
                self.project_activations_total,
                self.lease_reap_nodes_total,
            },
        );

        var first = true;
        var invite_it = self.invites.valueIterator();
        while (invite_it.next()) |invite| {
            if (!first) try out.append(self.allocator, ',');
            first = false;

            const escaped_id = try jsonEscape(self.allocator, invite.id);
            defer self.allocator.free(escaped_id);
            const escaped_token = try jsonEscape(self.allocator, invite.token);
            defer self.allocator.free(escaped_token);
            try out.writer(self.allocator).print(
                "{{\"id\":\"{s}\",\"token\":\"{s}\",\"created_at_ms\":{d},\"expires_at_ms\":{d},\"redeemed\":{s}}}",
                .{
                    escaped_id,
                    escaped_token,
                    invite.created_at_ms,
                    invite.expires_at_ms,
                    if (invite.redeemed) "true" else "false",
                },
            );
        }

        try out.appendSlice(self.allocator, "],\"nodes\":[");
        first = true;
        var node_it = self.nodes.valueIterator();
        while (node_it.next()) |node| {
            if (!first) try out.append(self.allocator, ',');
            first = false;

            const escaped_id = try jsonEscape(self.allocator, node.id);
            defer self.allocator.free(escaped_id);
            const escaped_name = try jsonEscape(self.allocator, node.name);
            defer self.allocator.free(escaped_name);
            const escaped_url = try jsonEscape(self.allocator, node.fs_url);
            defer self.allocator.free(escaped_url);
            const escaped_secret = try jsonEscape(self.allocator, node.secret);
            defer self.allocator.free(escaped_secret);
            const escaped_lease = try jsonEscape(self.allocator, node.lease_token);
            defer self.allocator.free(escaped_lease);

            try out.writer(self.allocator).print(
                "{{\"id\":\"{s}\",\"name\":\"{s}\",\"fs_url\":\"{s}\",\"secret\":\"{s}\",\"lease_token\":\"{s}\",\"joined_at_ms\":{d},\"last_seen_ms\":{d},\"lease_expires_at_ms\":{d}}}",
                .{
                    escaped_id,
                    escaped_name,
                    escaped_url,
                    escaped_secret,
                    escaped_lease,
                    node.joined_at_ms,
                    node.last_seen_ms,
                    node.lease_expires_at_ms,
                },
            );
        }

        try out.appendSlice(self.allocator, "],\"projects\":[");
        first = true;
        var project_it = self.projects.valueIterator();
        while (project_it.next()) |project| {
            if (!first) try out.append(self.allocator, ',');
            first = false;

            const escaped_id = try jsonEscape(self.allocator, project.id);
            defer self.allocator.free(escaped_id);
            const escaped_name = try jsonEscape(self.allocator, project.name);
            defer self.allocator.free(escaped_name);
            const escaped_vision = try jsonEscape(self.allocator, project.vision);
            defer self.allocator.free(escaped_vision);
            const escaped_status = try jsonEscape(self.allocator, project.status);
            defer self.allocator.free(escaped_status);
            const escaped_kind = try jsonEscape(self.allocator, projectKindName(project.kind));
            defer self.allocator.free(escaped_kind);
            const escaped_token = try jsonEscape(self.allocator, project.mutation_token);
            defer self.allocator.free(escaped_token);

            try out.writer(self.allocator).print(
                "{{\"id\":\"{s}\",\"name\":\"{s}\",\"vision\":\"{s}\",\"status\":\"{s}\",\"kind\":\"{s}\",\"is_delete_protected\":{s},\"mutation_token\":\"{s}\",\"created_at_ms\":{d},\"updated_at_ms\":{d},\"mounts\":[",
                .{
                    escaped_id,
                    escaped_name,
                    escaped_vision,
                    escaped_status,
                    escaped_kind,
                    if (project.is_delete_protected) "true" else "false",
                    escaped_token,
                    project.created_at_ms,
                    project.updated_at_ms,
                },
            );
            for (project.mounts.items, 0..) |mount, idx| {
                if (idx != 0) try out.append(self.allocator, ',');
                const escaped_path = try jsonEscape(self.allocator, mount.mount_path);
                defer self.allocator.free(escaped_path);
                const escaped_node = try jsonEscape(self.allocator, mount.node_id);
                defer self.allocator.free(escaped_node);
                const escaped_export = try jsonEscape(self.allocator, mount.export_name);
                defer self.allocator.free(escaped_export);
                try out.writer(self.allocator).print(
                    "{{\"mount_path\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"{s}\"}}",
                    .{ escaped_path, escaped_node, escaped_export },
                );
            }
            try out.appendSlice(self.allocator, "]}");
        }

        try out.appendSlice(self.allocator, "],\"active_project_by_agent\":[");
        first = true;
        var active_it = self.active_project_by_agent.iterator();
        while (active_it.next()) |entry| {
            if (!first) try out.append(self.allocator, ',');
            first = false;
            const escaped_agent = try jsonEscape(self.allocator, entry.key_ptr.*);
            defer self.allocator.free(escaped_agent);
            const escaped_project = try jsonEscape(self.allocator, entry.value_ptr.*);
            defer self.allocator.free(escaped_project);
            try out.writer(self.allocator).print(
                "{{\"agent_id\":\"{s}\",\"project_id\":\"{s}\"}}",
                .{ escaped_agent, escaped_project },
            );
        }

        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn restoreSnapshotFromJsonLocked(self: *ControlPlane, snapshot_json: []const u8) !void {
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, snapshot_json, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.InvalidSnapshot;
        const root = parsed.value.object;

        self.clearState();
        self.next_invite_id = 1;
        self.next_node_id = 1;
        self.next_project_id = 1;

        if (root.get("next")) |next_val| {
            if (next_val != .object) return error.InvalidSnapshot;
            self.next_invite_id = try getOptionalU64(next_val.object, "invite_id", 1);
            self.next_node_id = try getOptionalU64(next_val.object, "node_id", 1);
            self.next_project_id = try getOptionalU64(next_val.object, "project_id", 1);
        } else {
            self.next_invite_id = try getOptionalU64(root, "next_invite_id", 1);
            self.next_node_id = try getOptionalU64(root, "next_node_id", 1);
            self.next_project_id = try getOptionalU64(root, "next_project_id", 1);
        }

        if (root.get("metrics")) |metrics_val| {
            if (metrics_val != .object) return error.InvalidSnapshot;
            self.invites_created_total = try getOptionalU64(metrics_val.object, "invites_created_total", 0);
            self.invites_redeemed_total = try getOptionalU64(metrics_val.object, "invites_redeemed_total", 0);
            self.node_joins_total = try getOptionalU64(metrics_val.object, "node_joins_total", 0);
            self.node_lease_refresh_total = try getOptionalU64(metrics_val.object, "node_lease_refresh_total", 0);
            self.nodes_ensured_total = try getOptionalU64(metrics_val.object, "nodes_ensured_total", 0);
            self.node_deletes_total = try getOptionalU64(metrics_val.object, "node_deletes_total", 0);
            self.project_creates_total = try getOptionalU64(metrics_val.object, "project_creates_total", 0);
            self.project_updates_total = try getOptionalU64(metrics_val.object, "project_updates_total", 0);
            self.project_deletes_total = try getOptionalU64(metrics_val.object, "project_deletes_total", 0);
            self.project_token_rotates_total = try getOptionalU64(metrics_val.object, "project_token_rotates_total", 0);
            self.project_token_revokes_total = try getOptionalU64(metrics_val.object, "project_token_revokes_total", 0);
            self.mount_sets_total = try getOptionalU64(metrics_val.object, "mount_sets_total", 0);
            self.mount_removes_total = try getOptionalU64(metrics_val.object, "mount_removes_total", 0);
            self.project_activations_total = try getOptionalU64(metrics_val.object, "project_activations_total", 0);
            self.lease_reap_nodes_total = try getOptionalU64(metrics_val.object, "lease_reap_nodes_total", 0);
        }

        if (root.get("invites")) |invites_val| {
            if (invites_val != .array) return error.InvalidSnapshot;
            for (invites_val.array.items) |item| {
                if (item != .object) return error.InvalidSnapshot;
                var invite = Invite{
                    .id = try dupeRequiredString(self.allocator, item.object, "id"),
                    .token = try dupeRequiredString(self.allocator, item.object, "token"),
                    .created_at_ms = try getRequiredI64(item.object, "created_at_ms"),
                    .expires_at_ms = try getRequiredI64(item.object, "expires_at_ms"),
                    .redeemed = try getRequiredBool(item.object, "redeemed"),
                };
                errdefer invite.deinit(self.allocator);
                if (self.invites.contains(invite.id)) return error.InvalidSnapshot;
                try self.invites.put(self.allocator, invite.id, invite);
            }
        }

        if (root.get("nodes")) |nodes_val| {
            if (nodes_val != .array) return error.InvalidSnapshot;
            for (nodes_val.array.items) |item| {
                if (item != .object) return error.InvalidSnapshot;
                const fs_url = if (item.object.get("fs_url")) |url_val| blk: {
                    if (url_val != .string) return error.InvalidSnapshot;
                    break :blk try self.allocator.dupe(u8, url_val.string);
                } else try self.allocator.dupe(u8, "");
                var node = Node{
                    .id = try dupeRequiredString(self.allocator, item.object, "id"),
                    .name = try dupeRequiredString(self.allocator, item.object, "name"),
                    .fs_url = fs_url,
                    .secret = try dupeRequiredString(self.allocator, item.object, "secret"),
                    .lease_token = try dupeRequiredString(self.allocator, item.object, "lease_token"),
                    .joined_at_ms = try getRequiredI64(item.object, "joined_at_ms"),
                    .last_seen_ms = try getRequiredI64(item.object, "last_seen_ms"),
                    .lease_expires_at_ms = try getRequiredI64(item.object, "lease_expires_at_ms"),
                };
                errdefer node.deinit(self.allocator);
                if (self.nodes.contains(node.id)) return error.InvalidSnapshot;
                try self.nodes.put(self.allocator, node.id, node);
            }
        }

        if (root.get("projects")) |projects_val| {
            if (projects_val != .array) return error.InvalidSnapshot;
            for (projects_val.array.items) |item| {
                if (item != .object) return error.InvalidSnapshot;
                const kind = if (item.object.get("kind")) |kind_val| blk: {
                    if (kind_val != .string) return error.InvalidSnapshot;
                    break :blk parseProjectKind(kind_val.string);
                } else if (item.object.get("id")) |id_val|
                    if (id_val == .string and std.mem.eql(u8, id_val.string, spider_web_project_id))
                        ProjectKind.spider_web_builtin
                    else
                        ProjectKind.normal
                else
                    ProjectKind.normal;
                const is_delete_protected = if (item.object.get("is_delete_protected")) |protected_val| blk: {
                    if (protected_val != .bool) return error.InvalidSnapshot;
                    break :blk protected_val.bool;
                } else kind == .spider_web_builtin;
                var project = Project{
                    .id = try dupeRequiredString(self.allocator, item.object, "id"),
                    .name = try dupeRequiredString(self.allocator, item.object, "name"),
                    .vision = try dupeRequiredString(self.allocator, item.object, "vision"),
                    .status = try dupeRequiredString(self.allocator, item.object, "status"),
                    .kind = kind,
                    .is_delete_protected = is_delete_protected,
                    .mutation_token = if (item.object.get("mutation_token")) |token_val| blk: {
                        if (token_val != .string or token_val.string.len == 0) return error.InvalidSnapshot;
                        break :blk try self.allocator.dupe(u8, token_val.string);
                    } else try makeToken(self.allocator, "proj"),
                    .created_at_ms = try getRequiredI64(item.object, "created_at_ms"),
                    .updated_at_ms = try getRequiredI64(item.object, "updated_at_ms"),
                };
                errdefer project.deinit(self.allocator);
                if (self.projects.contains(project.id)) return error.InvalidSnapshot;

                const mounts_val = item.object.get("mounts") orelse return error.InvalidSnapshot;
                if (mounts_val != .array) return error.InvalidSnapshot;
                for (mounts_val.array.items) |mount_item| {
                    if (mount_item != .object) return error.InvalidSnapshot;
                    var mount = ProjectMount{
                        .mount_path = try dupeRequiredString(self.allocator, mount_item.object, "mount_path"),
                        .node_id = try dupeRequiredString(self.allocator, mount_item.object, "node_id"),
                        .export_name = try dupeRequiredString(self.allocator, mount_item.object, "export_name"),
                    };
                    errdefer mount.deinit(self.allocator);
                    try project.mounts.append(self.allocator, mount);
                }
                try self.projects.put(self.allocator, project.id, project);
            }
        }

        if (root.get("active_project_by_agent")) |active_val| {
            if (active_val != .array) return error.InvalidSnapshot;
            for (active_val.array.items) |item| {
                if (item != .object) return error.InvalidSnapshot;
                const agent_id = try dupeRequiredString(self.allocator, item.object, "agent_id");
                errdefer self.allocator.free(agent_id);
                const project_id = try dupeRequiredString(self.allocator, item.object, "project_id");
                errdefer self.allocator.free(project_id);
                if (self.active_project_by_agent.contains(agent_id)) return error.InvalidSnapshot;
                try self.active_project_by_agent.put(self.allocator, agent_id, project_id);
            }
        }

        // Normalize stale pointers from historic snapshots.
        var normalize_it = self.active_project_by_agent.iterator();
        while (normalize_it.next()) |entry| {
            if (entry.value_ptr.*.len == 0) continue;
            if (!self.projects.contains(entry.value_ptr.*)) {
                self.allocator.free(entry.value_ptr.*);
                entry.value_ptr.* = try self.allocator.dupe(u8, "");
            }
        }
    }
};

const ParsedPayload = std.json.Parsed(std.json.Value);

fn parsePayload(allocator: std.mem.Allocator, payload_json: ?[]const u8) !ParsedPayload {
    const raw = payload_json orelse "{}";
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    errdefer parsed.deinit();
    if (parsed.value != .object) return ControlPlaneError.InvalidPayload;
    return parsed;
}

fn getRequiredString(obj: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = obj.get(name) orelse return ControlPlaneError.MissingField;
    if (value != .string or value.string.len == 0) return ControlPlaneError.InvalidPayload;
    return value.string;
}

fn getOptionalString(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = obj.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn getOptionalUnsigned(obj: std.json.ObjectMap, name: []const u8, default_value: u64) !u64 {
    const value = obj.get(name) orelse return default_value;
    if (value != .integer or value.integer < 0) return ControlPlaneError.InvalidPayload;
    return @intCast(value.integer);
}

fn getOptionalBool(obj: std.json.ObjectMap, name: []const u8, default_value: bool) !bool {
    const value = obj.get(name) orelse return default_value;
    if (value != .bool) return ControlPlaneError.InvalidPayload;
    return value.bool;
}

fn getOptionalU64(obj: std.json.ObjectMap, name: []const u8, default_value: u64) !u64 {
    const value = obj.get(name) orelse return default_value;
    if (value != .integer or value.integer < 0) return error.InvalidSnapshot;
    return @intCast(value.integer);
}

fn dupeRequiredString(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    name: []const u8,
) ![]u8 {
    const value = obj.get(name) orelse return error.InvalidSnapshot;
    if (value != .string) return error.InvalidSnapshot;
    return allocator.dupe(u8, value.string);
}

fn getRequiredI64(obj: std.json.ObjectMap, name: []const u8) !i64 {
    const value = obj.get(name) orelse return error.InvalidSnapshot;
    if (value != .integer) return error.InvalidSnapshot;
    return value.integer;
}

fn getRequiredBool(obj: std.json.ObjectMap, name: []const u8) !bool {
    const value = obj.get(name) orelse return error.InvalidSnapshot;
    if (value != .bool) return error.InvalidSnapshot;
    return value.bool;
}

fn makeSequentialId(allocator: std.mem.Allocator, prefix: []const u8, counter: *u64) ![]u8 {
    const id = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ prefix, counter.* });
    counter.* += 1;
    return id;
}

fn makeToken(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    try out.writer(allocator).print("{s}-", .{prefix});
    for (bytes) |byte| {
        try out.writer(allocator).print("{x:0>2}", .{byte});
    }
    return out.toOwnedSlice(allocator);
}

fn appendNodeJson(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), node: Node) !void {
    const escaped_id = try jsonEscape(allocator, node.id);
    defer allocator.free(escaped_id);
    const escaped_name = try jsonEscape(allocator, node.name);
    defer allocator.free(escaped_name);
    const escaped_url = try jsonEscape(allocator, node.fs_url);
    defer allocator.free(escaped_url);
    try out.writer(allocator).print(
        "{{\"node_id\":\"{s}\",\"node_name\":\"{s}\",\"fs_url\":\"{s}\",\"joined_at_ms\":{d},\"last_seen_ms\":{d},\"lease_expires_at_ms\":{d}}}",
        .{ escaped_id, escaped_name, escaped_url, node.joined_at_ms, node.last_seen_ms, node.lease_expires_at_ms },
    );
}

fn appendProjectSummaryJson(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), project: Project) !void {
    const escaped_id = try jsonEscape(allocator, project.id);
    defer allocator.free(escaped_id);
    const escaped_name = try jsonEscape(allocator, project.name);
    defer allocator.free(escaped_name);
    const escaped_status = try jsonEscape(allocator, project.status);
    defer allocator.free(escaped_status);
    const escaped_kind = try jsonEscape(allocator, projectKindName(project.kind));
    defer allocator.free(escaped_kind);
    try out.writer(allocator).print(
        "{{\"project_id\":\"{s}\",\"name\":\"{s}\",\"status\":\"{s}\",\"kind\":\"{s}\",\"is_delete_protected\":{s},\"mount_count\":{d}}}",
        .{
            escaped_id,
            escaped_name,
            escaped_status,
            escaped_kind,
            if (project.is_delete_protected) "true" else "false",
            project.mounts.items.len,
        },
    );
}

fn appendMountJson(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), mount: ProjectMount) !void {
    const escaped_path = try jsonEscape(allocator, mount.mount_path);
    defer allocator.free(escaped_path);
    const escaped_node = try jsonEscape(allocator, mount.node_id);
    defer allocator.free(escaped_node);
    const escaped_export = try jsonEscape(allocator, mount.export_name);
    defer allocator.free(escaped_export);
    try out.writer(allocator).print(
        "{{\"mount_path\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"{s}\"}}",
        .{ escaped_path, escaped_node, escaped_export },
    );
}

fn appendWorkspaceMountJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    mount: ProjectMount,
    node: ?Node,
) !void {
    const escaped_path = try jsonEscape(allocator, mount.mount_path);
    defer allocator.free(escaped_path);
    const escaped_node = try jsonEscape(allocator, mount.node_id);
    defer allocator.free(escaped_node);
    const escaped_export = try jsonEscape(allocator, mount.export_name);
    defer allocator.free(escaped_export);

    if (node) |resolved| {
        const escaped_name = try jsonEscape(allocator, resolved.name);
        defer allocator.free(escaped_name);
        const escaped_url = try jsonEscape(allocator, resolved.fs_url);
        defer allocator.free(escaped_url);
        const escaped_auth = try jsonEscape(allocator, resolved.secret);
        defer allocator.free(escaped_auth);
        const online = resolved.lease_expires_at_ms > std.time.milliTimestamp();
        try out.writer(allocator).print(
            "{{\"mount_path\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"{s}\",\"node_name\":\"{s}\",\"fs_url\":\"{s}\",\"fs_auth_token\":\"{s}\",\"online\":{s}}}",
            .{
                escaped_path,
                escaped_node,
                escaped_export,
                escaped_name,
                escaped_url,
                escaped_auth,
                if (online) "true" else "false",
            },
        );
        return;
    }

    try out.writer(allocator).print(
        "{{\"mount_path\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"{s}\",\"node_name\":null,\"fs_url\":null,\"fs_auth_token\":null,\"online\":false}}",
        .{ escaped_path, escaped_node, escaped_export },
    );
}

fn appendDriftEntryJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    mount_path: []const u8,
    kind: []const u8,
    severity: DriftSeverity,
    selected_node_id: []const u8,
    desired_node_id: []const u8,
    message: []const u8,
) !void {
    const escaped_path = try jsonEscape(allocator, mount_path);
    defer allocator.free(escaped_path);
    const escaped_kind = try jsonEscape(allocator, kind);
    defer allocator.free(escaped_kind);
    const escaped_selected = try jsonEscape(allocator, selected_node_id);
    defer allocator.free(escaped_selected);
    const escaped_desired = try jsonEscape(allocator, desired_node_id);
    defer allocator.free(escaped_desired);
    const escaped_message = try jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    try out.writer(allocator).print(
        "{{\"mount_path\":\"{s}\",\"kind\":\"{s}\",\"severity\":\"{s}\",\"selected_node_id\":\"{s}\",\"desired_node_id\":\"{s}\",\"message\":\"{s}\"}}",
        .{
            escaped_path,
            escaped_kind,
            driftSeverityName(severity),
            escaped_selected,
            escaped_desired,
            escaped_message,
        },
    );
}

fn reconcileStateName(state: ReconcileState) []const u8 {
    return switch (state) {
        .idle => "idle",
        .pending => "pending",
        .running => "running",
        .degraded => "degraded",
    };
}

fn driftSeverityName(severity: DriftSeverity) []const u8 {
    return switch (severity) {
        .info => "info",
        .warning => "warning",
        .err => "error",
    };
}

fn projectKindName(kind: ProjectKind) []const u8 {
    return switch (kind) {
        .normal => normal_project_kind_name,
        .spider_web_builtin => spider_web_project_kind_name,
    };
}

fn parseProjectKind(value: []const u8) ProjectKind {
    if (std.mem.eql(u8, value, spider_web_project_kind_name)) return .spider_web_builtin;
    return .normal;
}

fn renderProjectPayload(allocator: std.mem.Allocator, project: Project, include_project_token: bool) ![]u8 {
    const escaped_id = try jsonEscape(allocator, project.id);
    defer allocator.free(escaped_id);
    const escaped_name = try jsonEscape(allocator, project.name);
    defer allocator.free(escaped_name);
    const escaped_vision = try jsonEscape(allocator, project.vision);
    defer allocator.free(escaped_vision);
    const escaped_status = try jsonEscape(allocator, project.status);
    defer allocator.free(escaped_status);
    const escaped_kind = try jsonEscape(allocator, projectKindName(project.kind));
    defer allocator.free(escaped_kind);
    const escaped_token = if (include_project_token) blk: {
        break :blk try jsonEscape(allocator, project.mutation_token);
    } else null;
    defer if (escaped_token) |token| allocator.free(token);

    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    try out.writer(allocator).print(
        "{{\"project_id\":\"{s}\",\"name\":\"{s}\",\"vision\":\"{s}\",\"status\":\"{s}\",\"kind\":\"{s}\",\"is_delete_protected\":{s},\"created_at_ms\":{d},\"updated_at_ms\":{d}",
        .{
            escaped_id,
            escaped_name,
            escaped_vision,
            escaped_status,
            escaped_kind,
            if (project.is_delete_protected) "true" else "false",
            project.created_at_ms,
            project.updated_at_ms,
        },
    );
    if (escaped_token) |token| {
        try out.writer(allocator).print(",\"project_token\":\"{s}\"", .{token});
    }
    try out.appendSlice(allocator, ",\"mounts\":[");
    for (project.mounts.items, 0..) |mount, idx| {
        if (idx != 0) try out.append(allocator, ',');
        try appendMountJson(allocator, &out, mount);
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn normalizeMountPath(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return ControlPlaneError.InvalidPayload;

    trimmed = std.mem.trim(u8, trimmed, "/");
    if (trimmed.len == 0) return allocator.dupe(u8, "/");

    return std.fmt.allocPrint(allocator, "/{s}", .{trimmed});
}

fn mountPathsOverlap(a: []const u8, b: []const u8) bool {
    if (std.mem.eql(u8, a, "/") or std.mem.eql(u8, b, "/")) return true;

    if (std.mem.startsWith(u8, a, b)) {
        return a.len > b.len and a[b.len] == '/';
    }
    if (std.mem.startsWith(u8, b, a)) {
        return b.len > a.len and b[a.len] == '/';
    }
    return false;
}

fn validateIdentifier(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return ControlPlaneError.InvalidPayload;
    for (value) |char| {
        if (std.ascii.isAlphanumeric(char)) continue;
        if (char == '-' or char == '_' or char == '.') continue;
        return ControlPlaneError.InvalidPayload;
    }
}

fn validateSecretToken(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return ControlPlaneError.InvalidPayload;
}

fn validateDisplayString(value: []const u8, max_len: usize) !void {
    if (value.len == 0 or value.len > max_len) return ControlPlaneError.InvalidPayload;
    for (value) |char| {
        if (char < 0x20) return ControlPlaneError.InvalidPayload;
    }
}

fn validateDisplayStringAllowEmpty(value: []const u8, max_len: usize) !void {
    if (value.len > max_len) return ControlPlaneError.InvalidPayload;
    for (value) |char| {
        if (char < 0x20) return ControlPlaneError.InvalidPayload;
    }
}

fn secureTokenEql(expected: []const u8, candidate: []const u8) bool {
    if (expected.len != candidate.len) return false;
    var diff: u8 = 0;
    for (expected, candidate) |lhs, rhs| {
        diff |= lhs ^ rhs;
    }
    return diff == 0;
}

fn validateExportName(value: []const u8) !void {
    try validateIdentifier(value, 128);
    if (std.mem.indexOfScalar(u8, value, '/')) |_| return ControlPlaneError.InvalidPayload;
}

fn validateFsUrl(value: []const u8) !void {
    if (!std.mem.startsWith(u8, value, "ws://")) return ControlPlaneError.InvalidPayload;
    if (std.mem.indexOf(u8, value, "/v2/fs") == null) return ControlPlaneError.InvalidPayload;
    if (value.len > 512) return ControlPlaneError.InvalidPayload;
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

fn loadStateEncryptionKey(allocator: std.mem.Allocator) ?[persistence_cipher.key_length]u8 {
    const raw = std.process.getEnvVarOwned(allocator, persistence_key_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => {
            std.log.warn("control-plane state encryption disabled: failed reading {s}: {s}", .{ persistence_key_env, @errorName(err) });
            return null;
        },
    };
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (trimmed.len != persistence_cipher.key_length * 2) {
        std.log.warn(
            "control-plane state encryption disabled: {s} must be {d} hex chars",
            .{ persistence_key_env, persistence_cipher.key_length * 2 },
        );
        return null;
    }

    var key: [persistence_cipher.key_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, trimmed) catch |err| {
        std.log.warn("control-plane state encryption disabled: invalid key in {s}: {s}", .{ persistence_key_env, @errorName(err) });
        return null;
    };
    std.log.info("control-plane state encryption enabled via {s}", .{persistence_key_env});
    return key;
}

fn isEncryptedSnapshotEnvelope(content_json: []const u8) bool {
    return std.mem.indexOf(u8, content_json, "\"enc\":\"aes-256-gcm\"") != null and
        std.mem.indexOf(u8, content_json, "\"ciphertext\"") != null and
        std.mem.indexOf(u8, content_json, "\"nonce\"") != null and
        std.mem.indexOf(u8, content_json, "\"tag\"") != null;
}

fn encryptSnapshotJson(
    allocator: std.mem.Allocator,
    snapshot_json: []const u8,
    key: [persistence_cipher.key_length]u8,
) ![]u8 {
    var nonce: [persistence_cipher.nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ciphertext = try allocator.alloc(u8, snapshot_json.len);
    defer allocator.free(ciphertext);
    var tag: [persistence_cipher.tag_length]u8 = undefined;
    persistence_cipher.encrypt(ciphertext, &tag, snapshot_json, persistence_aad, nonce, key);

    const encoded_nonce = try encodeBase64(allocator, &nonce);
    defer allocator.free(encoded_nonce);
    const encoded_tag = try encodeBase64(allocator, &tag);
    defer allocator.free(encoded_tag);
    const encoded_ciphertext = try encodeBase64(allocator, ciphertext);
    defer allocator.free(encoded_ciphertext);

    return std.fmt.allocPrint(
        allocator,
        "{{\"schema\":1,\"enc\":\"aes-256-gcm\",\"nonce\":\"{s}\",\"tag\":\"{s}\",\"ciphertext\":\"{s}\"}}",
        .{ encoded_nonce, encoded_tag, encoded_ciphertext },
    );
}

fn decryptSnapshotJson(
    allocator: std.mem.Allocator,
    envelope_json: []const u8,
    key: [persistence_cipher.key_length]u8,
) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, envelope_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidSnapshot;
    const obj = parsed.value.object;

    const enc = obj.get("enc") orelse return error.InvalidSnapshot;
    if (enc != .string or !std.mem.eql(u8, enc.string, "aes-256-gcm")) return error.InvalidSnapshot;
    const nonce_b64 = try getRequiredSnapshotString(obj, "nonce");
    const tag_b64 = try getRequiredSnapshotString(obj, "tag");
    const ciphertext_b64 = try getRequiredSnapshotString(obj, "ciphertext");

    const nonce_bytes = try decodeBase64(allocator, nonce_b64);
    defer allocator.free(nonce_bytes);
    if (nonce_bytes.len != persistence_cipher.nonce_length) return error.InvalidSnapshot;

    const tag_bytes = try decodeBase64(allocator, tag_b64);
    defer allocator.free(tag_bytes);
    if (tag_bytes.len != persistence_cipher.tag_length) return error.InvalidSnapshot;

    const ciphertext = try decodeBase64(allocator, ciphertext_b64);
    defer allocator.free(ciphertext);

    var nonce: [persistence_cipher.nonce_length]u8 = undefined;
    @memcpy(nonce[0..], nonce_bytes);
    var tag: [persistence_cipher.tag_length]u8 = undefined;
    @memcpy(tag[0..], tag_bytes);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    persistence_cipher.decrypt(plaintext, ciphertext, tag, persistence_aad, nonce, key) catch return error.AuthenticationFailed;
    return plaintext;
}

fn getRequiredSnapshotString(obj: std.json.ObjectMap, field: []const u8) ![]const u8 {
    const value = obj.get(field) orelse return error.InvalidSnapshot;
    if (value != .string or value.string.len == 0) return error.InvalidSnapshot;
    return value.string;
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

test "fs_control_plane: builtin spider web project is protected and primary-only" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const projects_json = try plane.listProjects();
    defer allocator.free(projects_json);
    try std.testing.expect(std.mem.indexOf(u8, projects_json, "\"project_id\":\"spider-web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, projects_json, "\"kind\":\"spider_web_builtin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, projects_json, "\"is_delete_protected\":true") != null);

    try std.testing.expectError(
        ControlPlaneError.ProjectProtected,
        plane.deleteProject("{\"project_id\":\"spider-web\",\"project_token\":\"token\"}"),
    );
    const state_json = try plane.dumpState();
    defer allocator.free(state_json);
    var parsed_state = try std.json.parseFromSlice(std.json.Value, allocator, state_json, .{});
    defer parsed_state.deinit();
    const projects_val = parsed_state.value.object.get("projects").?;
    try std.testing.expect(projects_val == .array);
    var spider_token: ?[]const u8 = null;
    for (projects_val.array.items) |item| {
        if (item != .object) continue;
        const id_val = item.object.get("id") orelse continue;
        if (id_val != .string) continue;
        if (!std.mem.eql(u8, id_val.string, spider_web_project_id)) continue;
        const token_val = item.object.get("mutation_token") orelse continue;
        if (token_val == .string) {
            spider_token = token_val.string;
            break;
        }
    }
    try std.testing.expect(spider_token != null);
    const update_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"name\":\"Renamed\",\"vision\":\"Changed\"}}",
        .{ spider_web_project_id, spider_token.? },
    );
    defer allocator.free(update_req);
    try std.testing.expectError(
        ControlPlaneError.ProjectProtected,
        plane.updateProject(update_req),
    );
    try std.testing.expectError(
        ControlPlaneError.ProjectAssignmentForbidden,
        plane.activateProject("agent-worker", "{\"project_id\":\"spider-web\",\"project_token\":\"token\"}"),
    );
    try std.testing.expectError(
        ControlPlaneError.ProjectAssignmentForbidden,
        plane.workspaceStatus("agent-worker", "{\"project_id\":\"spider-web\"}"),
    );

    const activated = try plane.activateProject("default", "{\"project_id\":\"spider-web\"}");
    defer allocator.free(activated);
    try std.testing.expect(std.mem.indexOf(u8, activated, "\"project_id\":\"spider-web\"") != null);

    const status = try plane.workspaceStatus("default", "{\"project_id\":\"spider-web\"}");
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"project_id\":\"spider-web\"") != null);
}

test "fs_control_plane: builtin spider web mount can be bound from local node" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const joined = try plane.ensureNode("spiderweb-local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(joined);
    var parsed_join = try std.json.parseFromSlice(std.json.Value, allocator, joined, .{});
    defer parsed_join.deinit();
    const node_id = parsed_join.value.object.get("node_id").?.string;

    try plane.ensureSpiderWebMount(node_id, "spider-web-root");

    const status = try plane.workspaceStatus("default", "{\"project_id\":\"spider-web\"}");
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"project_id\":\"spider-web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mount_path\":\"/workspace\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"export_name\":\"spider-web-root\"") != null);
}

test "fs_control_plane: builtin spider web mounts support namespace topology" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const joined = try plane.ensureNode("spiderweb-local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(joined);
    var parsed_join = try std.json.parseFromSlice(std.json.Value, allocator, joined, .{});
    defer parsed_join.deinit();
    const node_id = parsed_join.value.object.get("node_id").?.string;

    const mounts = [_]SpiderWebMountSpec{
        .{ .mount_path = "/meta", .export_name = "meta" },
        .{ .mount_path = "/capabilities", .export_name = "capabilities" },
        .{ .mount_path = "/jobs", .export_name = "jobs" },
        .{ .mount_path = "/workspace", .export_name = "workspace" },
    };
    try plane.ensureSpiderWebMounts(node_id, &mounts);

    const status = try plane.workspaceStatus("default", "{\"project_id\":\"spider-web\"}");
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mount_path\":\"/meta\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mount_path\":\"/capabilities\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mount_path\":\"/jobs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"mount_path\":\"/workspace\"") != null);
}

test "fs_control_plane: invite join lease flow works" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    try std.testing.expect(std.mem.indexOf(u8, invite_json, "\"invite_token\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer parsed.deinit();
    const token = parsed.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    try std.testing.expect(std.mem.indexOf(u8, join_json, "\"node_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, join_json, "\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"") != null);

    var join_parsed = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer join_parsed.deinit();
    const node_id = join_parsed.value.object.get("node_id").?.string;
    const secret = join_parsed.value.object.get("node_secret").?.string;

    const refresh_req = try std.fmt.allocPrint(
        allocator,
        "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"fs_url\":\"ws://127.0.0.1:28891/v2/fs\"}}",
        .{ node_id, secret },
    );
    defer allocator.free(refresh_req);
    const refresh_json = try plane.refreshNodeLease(refresh_req);
    defer allocator.free(refresh_json);
    try std.testing.expect(std.mem.indexOf(u8, refresh_json, "\"lease_token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, refresh_json, "\"fs_url\":\"ws://127.0.0.1:28891/v2/fs\"") != null);
}

test "fs_control_plane: project mount conflict is rejected" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var parsed_invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer parsed_invite.deinit();
    const token = parsed_invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(allocator, "{{\"invite_token\":\"{s}\"}}", .{token});
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var parsed_join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer parsed_join.deinit();
    const node_id = parsed_join.value.object.get("node_id").?.string;

    const create_json = try plane.createProject("{\"name\":\"Demo\"}");
    defer allocator.free(create_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, create_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const mount_a = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_id },
    );
    defer allocator.free(mount_a);
    const first = try plane.setProjectMount(mount_a);
    defer allocator.free(first);

    const mount_b = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src/lib\"}}",
        .{ project_id, project_token, node_id },
    );
    defer allocator.free(mount_b);
    try std.testing.expectError(ControlPlaneError.MountConflict, plane.setProjectMount(mount_b));
}

test "fs_control_plane: project mutation requires valid project_token" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var parsed_invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer parsed_invite.deinit();
    const token = parsed_invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var parsed_join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer parsed_join.deinit();
    const node_id = parsed_join.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"Secure\"}");
    defer allocator.free(project_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;

    const bad_mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"not-the-token\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, node_id },
    );
    defer allocator.free(bad_mount_req);
    try std.testing.expectError(ControlPlaneError.ProjectAuthFailed, plane.setProjectMount(bad_mount_req));
}

test "fs_control_plane: identical mount path can be used for failover nodes" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_a_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_a_json);
    var invite_a = try std.json.parseFromSlice(std.json.Value, allocator, invite_a_json, .{});
    defer invite_a.deinit();
    const token_a = invite_a.value.object.get("invite_token").?.string;

    const join_a_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token_a},
    );
    defer allocator.free(join_a_req);
    const join_a_json = try plane.nodeJoin(join_a_req);
    defer allocator.free(join_a_json);
    var join_a = try std.json.parseFromSlice(std.json.Value, allocator, join_a_json, .{});
    defer join_a.deinit();
    const node_a = join_a.value.object.get("node_id").?.string;

    const invite_b_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_b_json);
    var invite_b = try std.json.parseFromSlice(std.json.Value, allocator, invite_b_json, .{});
    defer invite_b.deinit();
    const token_b = invite_b.value.object.get("invite_token").?.string;

    const join_b_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"beta\",\"fs_url\":\"ws://127.0.0.1:18892/v2/fs\"}}",
        .{token_b},
    );
    defer allocator.free(join_b_req);
    const join_b_json = try plane.nodeJoin(join_b_req);
    defer allocator.free(join_b_json);
    var join_b = try std.json.parseFromSlice(std.json.Value, allocator, join_b_json, .{});
    defer join_b.deinit();
    const node_b = join_b.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"Failover\"}");
    defer allocator.free(project_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const mount_a = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_a },
    );
    defer allocator.free(mount_a);
    const first = try plane.setProjectMount(mount_a);
    defer allocator.free(first);

    const mount_b = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_b },
    );
    defer allocator.free(mount_b);
    const second = try plane.setProjectMount(mount_b);
    defer allocator.free(second);

    try std.testing.expect(std.mem.indexOf(u8, second, "\"node_id\":\"node-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, second, "\"node_id\":\"node-2\"") != null);
}

test "fs_control_plane: removeProjectMount supports path-wide and targeted failover removal" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_a_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_a_json);
    var invite_a = try std.json.parseFromSlice(std.json.Value, allocator, invite_a_json, .{});
    defer invite_a.deinit();
    const token_a = invite_a.value.object.get("invite_token").?.string;

    const join_a_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token_a},
    );
    defer allocator.free(join_a_req);
    const join_a_json = try plane.nodeJoin(join_a_req);
    defer allocator.free(join_a_json);
    var join_a = try std.json.parseFromSlice(std.json.Value, allocator, join_a_json, .{});
    defer join_a.deinit();
    const node_a = join_a.value.object.get("node_id").?.string;

    const invite_b_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_b_json);
    var invite_b = try std.json.parseFromSlice(std.json.Value, allocator, invite_b_json, .{});
    defer invite_b.deinit();
    const token_b = invite_b.value.object.get("invite_token").?.string;

    const join_b_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"beta\",\"fs_url\":\"ws://127.0.0.1:18892/v2/fs\"}}",
        .{token_b},
    );
    defer allocator.free(join_b_req);
    const join_b_json = try plane.nodeJoin(join_b_req);
    defer allocator.free(join_b_json);
    var join_b = try std.json.parseFromSlice(std.json.Value, allocator, join_b_json, .{});
    defer join_b.deinit();
    const node_b = join_b.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"FailoverRemove\"}");
    defer allocator.free(project_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const mount_a = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_a },
    );
    defer allocator.free(mount_a);
    const first = try plane.setProjectMount(mount_a);
    defer allocator.free(first);

    const mount_b = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_b },
    );
    defer allocator.free(mount_b);
    const second = try plane.setProjectMount(mount_b);
    defer allocator.free(second);

    const remove_targeted = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"mount_path\":\"/src\",\"node_id\":\"{s}\",\"export_name\":\"work\"}}",
        .{ project_id, project_token, node_a },
    );
    defer allocator.free(remove_targeted);
    const targeted_removed = try plane.removeProjectMount(remove_targeted);
    defer allocator.free(targeted_removed);
    const node_a_entry = try std.fmt.allocPrint(allocator, "\"node_id\":\"{s}\"", .{node_a});
    defer allocator.free(node_a_entry);
    const node_b_entry = try std.fmt.allocPrint(allocator, "\"node_id\":\"{s}\"", .{node_b});
    defer allocator.free(node_b_entry);
    try std.testing.expect(std.mem.indexOf(u8, targeted_removed, node_a_entry) == null);
    try std.testing.expect(std.mem.indexOf(u8, targeted_removed, node_b_entry) != null);

    const remove_all = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token },
    );
    defer allocator.free(remove_all);
    const all_removed = try plane.removeProjectMount(remove_all);
    defer allocator.free(all_removed);
    try std.testing.expect(std.mem.indexOf(u8, all_removed, "\"mounts\":[]") != null);
}

test "fs_control_plane: lease reaper removes expired nodes and project mounts" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer invite.deinit();
    const token = invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"ephemeral\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer join.deinit();
    const node_id = join.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"Lease GC\"}");
    defer allocator.free(project_json);
    var parsed_project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer parsed_project.deinit();
    const project_id = parsed_project.value.object.get("project_id").?.string;
    const project_token = parsed_project.value.object.get("project_token").?.string;

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    plane.mutex.lock();
    if (plane.nodes.getPtr(node_id)) |node| {
        node.lease_expires_at_ms = 0;
    }
    _ = plane.reapExpiredLeasesLocked(std.time.milliTimestamp());
    plane.mutex.unlock();

    const nodes_json = try plane.listNodes();
    defer allocator.free(nodes_json);
    try std.testing.expect(std.mem.indexOf(u8, nodes_json, node_id) == null);

    const get_project_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\"}}",
        .{project_id},
    );
    defer allocator.free(get_project_req);
    const project_after = try plane.getProject(get_project_req);
    defer allocator.free(project_after);
    try std.testing.expect(std.mem.indexOf(u8, project_after, "\"mounts\":[]") != null);
}

test "fs_control_plane: ensureNode upserts by node name" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const created = try plane.ensureNode("local", "ws://127.0.0.1:18891/v2/fs", 60_000);
    defer allocator.free(created);
    try std.testing.expect(std.mem.indexOf(u8, created, "\"node_id\":\"node-1\"") != null);

    const updated = try plane.ensureNode("local", "ws://127.0.0.1:28891/v2/fs", 60_000);
    defer allocator.free(updated);
    try std.testing.expect(std.mem.indexOf(u8, updated, "\"node_id\":\"node-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, updated, "\"fs_url\":\"ws://127.0.0.1:28891/v2/fs\"") != null);

    const nodes_json = try plane.listNodes();
    defer allocator.free(nodes_json);
    try std.testing.expect(std.mem.indexOf(u8, nodes_json, "\"node_id\":\"node-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, nodes_json, "\"node_id\":\"node-2\"") == null);
}

test "fs_control_plane: metricsJson reports mutation counters" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer invite.deinit();
    const token = invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer join.deinit();
    const node_id = join.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"Metrics\"}");
    defer allocator.free(project_json);
    var project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project.deinit();
    const project_id = project.value.object.get("project_id").?.string;
    const project_token = project.value.object.get("project_token").?.string;

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    const activate_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ project_id, project_token },
    );
    defer allocator.free(activate_req);
    const activated = try plane.activateProject("agent-metrics", activate_req);
    defer allocator.free(activated);

    const metrics_json = try plane.metricsJson();
    defer allocator.free(metrics_json);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"created_total\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"joins_total\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"mount_sets_total\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, metrics_json, "\"activations_total\":1") != null);
}

test "fs_control_plane: rotate and revoke project tokens invalidate previous token" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer invite.deinit();
    const invite_token = invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{invite_token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer join.deinit();
    const node_id = join.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"TokenOps\"}");
    defer allocator.free(project_json);
    var project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project.deinit();
    const project_id = project.value.object.get("project_id").?.string;
    const token_1 = project.value.object.get("project_token").?.string;

    const rotate_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ project_id, token_1 },
    );
    defer allocator.free(rotate_req);
    const rotate_json = try plane.rotateProjectToken(rotate_req);
    defer allocator.free(rotate_json);
    var rotate = try std.json.parseFromSlice(std.json.Value, allocator, rotate_json, .{});
    defer rotate.deinit();
    const token_2 = rotate.value.object.get("project_token").?.string;
    try std.testing.expect(!std.mem.eql(u8, token_1, token_2));

    const mount_old_token = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, token_1, node_id },
    );
    defer allocator.free(mount_old_token);
    try std.testing.expectError(ControlPlaneError.ProjectAuthFailed, plane.setProjectMount(mount_old_token));

    const mount_new_token = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, token_2, node_id },
    );
    defer allocator.free(mount_new_token);
    const mounted = try plane.setProjectMount(mount_new_token);
    defer allocator.free(mounted);

    const revoke_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ project_id, token_2 },
    );
    defer allocator.free(revoke_req);
    const revoke_json = try plane.revokeProjectToken(revoke_req);
    defer allocator.free(revoke_json);
    var revoke = try std.json.parseFromSlice(std.json.Value, allocator, revoke_json, .{});
    defer revoke.deinit();
    const token_3 = revoke.value.object.get("project_token").?.string;
    try std.testing.expect(!std.mem.eql(u8, token_2, token_3));

    const remove_old_token = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"mount_path\":\"/src\"}}",
        .{ project_id, token_2 },
    );
    defer allocator.free(remove_old_token);
    try std.testing.expectError(ControlPlaneError.ProjectAuthFailed, plane.removeProjectMount(remove_old_token));

    const remove_new_token = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"mount_path\":\"/src\"}}",
        .{ project_id, token_3 },
    );
    defer allocator.free(remove_new_token);
    const removed = try plane.removeProjectMount(remove_new_token);
    defer allocator.free(removed);
}

test "fs_control_plane: workspaceStatus supports explicit project selection" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const invite_json = try plane.createNodeInvite(null);
    defer allocator.free(invite_json);
    var invite = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
    defer invite.deinit();
    const invite_token = invite.value.object.get("invite_token").?.string;

    const join_req = try std.fmt.allocPrint(
        allocator,
        "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\"}}",
        .{invite_token},
    );
    defer allocator.free(join_req);
    const join_json = try plane.nodeJoin(join_req);
    defer allocator.free(join_json);
    var join = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
    defer join.deinit();
    const node_id = join.value.object.get("node_id").?.string;

    const project_json = try plane.createProject("{\"name\":\"Selector\"}");
    defer allocator.free(project_json);
    var project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project.deinit();
    const project_id = project.value.object.get("project_id").?.string;
    const project_token = project.value.object.get("project_token").?.string;

    const mount_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
        .{ project_id, project_token, node_id },
    );
    defer allocator.free(mount_req);
    const mounted = try plane.setProjectMount(mount_req);
    defer allocator.free(mounted);

    const no_selection = try plane.workspaceStatus("agent-selector", null);
    defer allocator.free(no_selection);
    try std.testing.expect(std.mem.indexOf(u8, no_selection, "\"project_id\":null") != null);

    const selected_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
        .{ project_id, project_token },
    );
    defer allocator.free(selected_req);
    const selected = try plane.workspaceStatus("agent-selector", selected_req);
    defer allocator.free(selected);
    try std.testing.expect(std.mem.indexOf(u8, selected, project_id) != null);
    try std.testing.expect(std.mem.indexOf(u8, selected, "\"mount_path\":\"/src\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, selected, "\"fs_auth_token\":\"") != null);

    const selected_without_token = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\"}}",
        .{project_id},
    );
    defer allocator.free(selected_without_token);
    try std.testing.expectError(
        ControlPlaneError.ProjectAuthFailed,
        plane.workspaceStatus("agent-selector", selected_without_token),
    );

    try std.testing.expectError(
        ControlPlaneError.ProjectNotFound,
        plane.workspaceStatus("agent-selector", "{\"project_id\":\"proj-missing\"}"),
    );
}

test "fs_control_plane: projectUp requires project_token for existing non-builtin project" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const project_json = try plane.createProject("{\"name\":\"UpAuth\"}");
    defer allocator.free(project_json);
    var project = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
    defer project.deinit();
    const project_id = project.value.object.get("project_id").?.string;
    const project_token = project.value.object.get("project_token").?.string;

    const missing_token_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"status\":\"paused\"}}",
        .{project_id},
    );
    defer allocator.free(missing_token_req);
    try std.testing.expectError(ControlPlaneError.MissingField, plane.projectUp("agent-up", missing_token_req));

    const bad_token_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"bad-token\",\"status\":\"paused\"}}",
        .{project_id},
    );
    defer allocator.free(bad_token_req);
    try std.testing.expectError(ControlPlaneError.ProjectAuthFailed, plane.projectUp("agent-up", bad_token_req));

    const missing_token_primary_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"status\":\"paused\"}}",
        .{project_id},
    );
    defer allocator.free(missing_token_primary_req);
    try std.testing.expectError(ControlPlaneError.MissingField, plane.projectUp("default", missing_token_primary_req));

    const bad_token_primary_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"bad-token\",\"status\":\"paused\"}}",
        .{project_id},
    );
    defer allocator.free(bad_token_primary_req);
    try std.testing.expectError(ControlPlaneError.ProjectAuthFailed, plane.projectUp("default", bad_token_primary_req));

    const ok_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"status\":\"paused\",\"activate\":false}}",
        .{ project_id, project_token },
    );
    defer allocator.free(ok_req);
    const ok_json = try plane.projectUp("agent-up", ok_req);
    defer allocator.free(ok_json);
    try std.testing.expect(std.mem.indexOf(u8, ok_json, "\"created\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, ok_json, "\"activated\":false") != null);

    const get_req = try std.fmt.allocPrint(allocator, "{{\"project_id\":\"{s}\"}}", .{project_id});
    defer allocator.free(get_req);
    const get_json = try plane.getProject(get_req);
    defer allocator.free(get_json);
    try std.testing.expect(std.mem.indexOf(u8, get_json, "\"status\":\"paused\"") != null);
}

test "fs_control_plane: project create/up allow omitted and empty vision" {
    const allocator = std.testing.allocator;
    var plane = ControlPlane.init(allocator);
    defer plane.deinit();

    const created = try plane.createProject("{\"name\":\"Visionless\"}");
    defer allocator.free(created);
    try std.testing.expect(std.mem.indexOf(u8, created, "\"vision\":\"\"") != null);

    var parsed_created = try std.json.parseFromSlice(std.json.Value, allocator, created, .{});
    defer parsed_created.deinit();
    const project_id = parsed_created.value.object.get("project_id").?.string;
    const project_token = parsed_created.value.object.get("project_token").?.string;

    const clear_req = try std.fmt.allocPrint(
        allocator,
        "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"vision\":\"\"}}",
        .{ project_id, project_token },
    );
    defer allocator.free(clear_req);
    const cleared = try plane.projectUp("agent-vision", clear_req);
    defer allocator.free(cleared);
    try std.testing.expect(std.mem.indexOf(u8, cleared, "\"created\":false") != null);

    const get_req = try std.fmt.allocPrint(allocator, "{{\"project_id\":\"{s}\"}}", .{project_id});
    defer allocator.free(get_req);
    const fetched = try plane.getProject(get_req);
    defer allocator.free(fetched);
    try std.testing.expect(std.mem.indexOf(u8, fetched, "\"vision\":\"\"") != null);

    const up_created = try plane.projectUp("agent-vision", "{\"name\":\"UpNoVision\"}");
    defer allocator.free(up_created);
    try std.testing.expect(std.mem.indexOf(u8, up_created, "\"created\":true") != null);
}

test "fs_control_plane: snapshot encryption envelope roundtrip" {
    const allocator = std.testing.allocator;
    const sample = "{\"schema\":1,\"hello\":\"world\"}";
    const key = [_]u8{0x5A} ** persistence_cipher.key_length;
    const encrypted = try encryptSnapshotJson(allocator, sample, key);
    defer allocator.free(encrypted);
    try std.testing.expect(isEncryptedSnapshotEnvelope(encrypted));

    const decrypted = try decryptSnapshotJson(allocator, encrypted, key);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(sample, decrypted);
}

test "fs_control_plane: persistence restores nodes projects mounts and active workspace" {
    const allocator = std.testing.allocator;
    const dir = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/fs-control-plane-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};

    try std.fs.cwd().makePath(dir);

    var expected_node_id: ?[]u8 = null;
    defer if (expected_node_id) |id| allocator.free(id);
    var expected_project_id: ?[]u8 = null;
    defer if (expected_project_id) |id| allocator.free(id);
    var expected_project_token: ?[]u8 = null;
    defer if (expected_project_token) |token| allocator.free(token);

    {
        var plane = ControlPlane.initWithPersistence(allocator, dir, "control-plane.db");
        defer plane.deinit();

        const invite_json = try plane.createNodeInvite(null);
        defer allocator.free(invite_json);
        var invite_parsed = try std.json.parseFromSlice(std.json.Value, allocator, invite_json, .{});
        defer invite_parsed.deinit();
        const token = invite_parsed.value.object.get("invite_token").?.string;

        const join_req = try std.fmt.allocPrint(
            allocator,
            "{{\"invite_token\":\"{s}\",\"node_name\":\"alpha\",\"fs_url\":\"ws://127.0.0.1:38891/v2/fs\"}}",
            .{token},
        );
        defer allocator.free(join_req);
        const join_json = try plane.nodeJoin(join_req);
        defer allocator.free(join_json);
        var join_parsed = try std.json.parseFromSlice(std.json.Value, allocator, join_json, .{});
        defer join_parsed.deinit();
        expected_node_id = try allocator.dupe(u8, join_parsed.value.object.get("node_id").?.string);

        const project_json = try plane.createProject("{\"name\":\"Demo\",\"vision\":\"dist fs\"}");
        defer allocator.free(project_json);
        var project_parsed = try std.json.parseFromSlice(std.json.Value, allocator, project_json, .{});
        defer project_parsed.deinit();
        expected_project_id = try allocator.dupe(u8, project_parsed.value.object.get("project_id").?.string);
        const project_token = project_parsed.value.object.get("project_token").?.string;
        expected_project_token = try allocator.dupe(u8, project_token);

        const mount_req = try std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/src\"}}",
            .{ expected_project_id.?, project_token, expected_node_id.? },
        );
        defer allocator.free(mount_req);
        const mounted = try plane.setProjectMount(mount_req);
        defer allocator.free(mounted);

        const activate_req = try std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\"}}",
            .{ expected_project_id.?, project_token },
        );
        defer allocator.free(activate_req);
        const activated = try plane.activateProject("agent-alpha", activate_req);
        defer allocator.free(activated);
    }

    {
        var plane = ControlPlane.initWithPersistence(allocator, dir, "control-plane.db");
        defer plane.deinit();

        const nodes_json = try plane.listNodes();
        defer allocator.free(nodes_json);
        try std.testing.expect(std.mem.indexOf(u8, nodes_json, expected_node_id.?) != null);

        const project_req = try std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\"}}",
            .{expected_project_id.?},
        );
        defer allocator.free(project_req);
        const project_json = try plane.getProject(project_req);
        defer allocator.free(project_json);
        try std.testing.expect(std.mem.indexOf(u8, project_json, "\"mount_path\":\"/src\"") != null);

        const remount_req = try std.fmt.allocPrint(
            allocator,
            "{{\"project_id\":\"{s}\",\"project_token\":\"{s}\",\"node_id\":\"{s}\",\"export_name\":\"work\",\"mount_path\":\"/restored\"}}",
            .{ expected_project_id.?, expected_project_token.?, expected_node_id.? },
        );
        defer allocator.free(remount_req);
        const remounted = try plane.setProjectMount(remount_req);
        defer allocator.free(remounted);
        try std.testing.expect(std.mem.indexOf(u8, remounted, "\"mount_path\":\"/restored\"") != null);

        const status = try plane.workspaceStatus("agent-alpha", null);
        defer allocator.free(status);
        try std.testing.expect(std.mem.indexOf(u8, status, expected_project_id.?) != null);
        try std.testing.expect(std.mem.indexOf(u8, status, "\"fs_url\":\"ws://127.0.0.1:38891/v2/fs\"") != null);

        const invite2 = try plane.createNodeInvite(null);
        defer allocator.free(invite2);
        try std.testing.expect(std.mem.indexOf(u8, invite2, "\"invite_id\":\"invite-2\"") != null);
    }
}
