const std = @import("std");
const fs_router = @import("acheron_fs_router");
const mount_provider = @import("spiderweb_mount_provider");
const namespace_client_mod = @import("namespace_client.zig");

const HybridContext = struct {
    allocator: std.mem.Allocator,
    router: *fs_router.Router,
    namespace: *namespace_client_mod.NamespaceClient,
    mount_paths: [][]u8,

    fn deinit(self: *HybridContext) void {
        for (self.mount_paths) |mount_path| self.allocator.free(mount_path);
        self.allocator.free(self.mount_paths);
        self.allocator.destroy(self);
    }
};

pub fn init(
    allocator: std.mem.Allocator,
    router: *fs_router.Router,
    namespace: *namespace_client_mod.NamespaceClient,
) !mount_provider.Provider {
    const ctx = try allocator.create(HybridContext);
    errdefer allocator.destroy(ctx);

    const count = router.endpointCount();
    const mount_paths = try allocator.alloc([]u8, count);
    errdefer allocator.free(mount_paths);

    for (0..count) |idx| {
        const mount_path = router.endpointMountPath(idx) orelse return error.InvalidResponse;
        mount_paths[idx] = try allocator.dupe(u8, mount_path);
    }

    ctx.* = .{
        .allocator = allocator,
        .router = router,
        .namespace = namespace,
        .mount_paths = mount_paths,
    };

    return .{
        .allocator = allocator,
        .ctx = ctx,
        .vtable = &hybrid_vtable,
    };
}

const hybrid_vtable: mount_provider.Provider.VTable = .{
    .deinit = hybridDeinit,
    .getattr = hybridGetattr,
    .readdir = hybridReaddir,
    .statfs = hybridStatfs,
    .open = hybridOpen,
    .read = hybridRead,
    .release = hybridRelease,
    .create = hybridCreate,
    .write = hybridWrite,
    .truncate = hybridTruncate,
    .unlink = hybridUnlink,
    .mkdir = hybridMkdir,
    .rmdir = hybridRmdir,
    .rename = hybridRename,
    .symlink = hybridSymlink,
    .setxattr = hybridSetxattr,
    .getxattr = hybridGetxattr,
    .listxattr = hybridListxattr,
    .removexattr = hybridRemovexattr,
    .lock = hybridLock,
};

fn asCtx(ctx: *anyopaque) *HybridContext {
    return @ptrCast(@alignCast(ctx));
}

fn routeToRouter(ctx: *HybridContext, path: []const u8) bool {
    const normalized = normalizeAbsolutePath(path);
    for (ctx.mount_paths) |mount_path| {
        if (pathMatchesMount(normalized, mount_path)) return true;
    }
    return false;
}

fn pathMatchesMount(path: []const u8, mount_path: []const u8) bool {
    const normalized_mount = normalizeAbsolutePath(mount_path);
    if (std.mem.eql(u8, path, normalized_mount)) return true;
    if (std.mem.eql(u8, normalized_mount, "/")) return true;
    if (!std.mem.startsWith(u8, path, normalized_mount)) return false;
    return path.len > normalized_mount.len and path[normalized_mount.len] == '/';
}

fn normalizeAbsolutePath(path: []const u8) []const u8 {
    if (path.len == 0) return "/";
    if (path.len > 1 and path[path.len - 1] == '/') return std.mem.trimRight(u8, path, "/");
    return path;
}

fn hybridDeinit(ctx: *anyopaque, allocator: std.mem.Allocator) void {
    _ = allocator;
    asCtx(ctx).deinit();
}

fn hybridGetattr(ctx: *anyopaque, path: []const u8) ![]u8 {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.getattr(path);
    return self.namespace.getattr(path);
}

fn hybridReaddir(ctx: *anyopaque, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.readdir(path, cookie, max_entries);
    return self.namespace.readdir(path, cookie, max_entries);
}

fn hybridStatfs(ctx: *anyopaque, path: []const u8) ![]u8 {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.statfs(path);
    return self.namespace.statfs(path);
}

fn hybridOpen(ctx: *anyopaque, path: []const u8, flags: u32) !mount_provider.OpenFile {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return .{ .router = try self.router.open(path, flags) };
    return .{ .namespace = try self.namespace.open(path, flags) };
}

fn hybridRead(ctx: *anyopaque, file: mount_provider.OpenFile, off: u64, len: u32) ![]u8 {
    const self = asCtx(ctx);
    return switch (file) {
        .router => |router_file| self.router.read(router_file, off, len),
        .namespace => |namespace_file| self.namespace.read(namespace_file, off, len),
    };
}

fn hybridRelease(ctx: *anyopaque, file: mount_provider.OpenFile) !void {
    const self = asCtx(ctx);
    switch (file) {
        .router => |router_file| try self.router.close(router_file),
        .namespace => |namespace_file| try self.namespace.release(namespace_file),
    }
}

fn hybridCreate(ctx: *anyopaque, path: []const u8, mode: u32, flags: u32) !mount_provider.OpenFile {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return .{ .router = try self.router.create(path, mode, flags) };
    return .{ .namespace = try self.namespace.create(path, mode, flags) };
}

fn hybridWrite(ctx: *anyopaque, file: mount_provider.OpenFile, off: u64, data: []const u8) !u32 {
    const self = asCtx(ctx);
    return switch (file) {
        .router => |router_file| self.router.write(router_file, off, data),
        .namespace => |namespace_file| self.namespace.write(namespace_file, off, data),
    };
}

fn hybridTruncate(ctx: *anyopaque, path: []const u8, size: u64) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.truncate(path, size);
    return self.namespace.truncate(path, size);
}

fn hybridUnlink(ctx: *anyopaque, path: []const u8) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.unlink(path);
    return self.namespace.unlink(path);
}

fn hybridMkdir(ctx: *anyopaque, path: []const u8) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.mkdir(path);
    return self.namespace.mkdir(path);
}

fn hybridRmdir(ctx: *anyopaque, path: []const u8) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.rmdir(path);
    return self.namespace.rmdir(path);
}

fn hybridRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) !void {
    const self = asCtx(ctx);
    const old_router = routeToRouter(self, old_path);
    const new_router = routeToRouter(self, new_path);
    if (old_router and new_router) return self.router.rename(old_path, new_path);
    if (!old_router and !new_router) return self.namespace.rename(old_path, new_path);
    return error.CrossEndpointRename;
}

fn hybridSymlink(ctx: *anyopaque, target: []const u8, link_path: []const u8) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, link_path)) return self.router.symlink(target, link_path);
    return error.OperationNotSupported;
}

fn hybridSetxattr(ctx: *anyopaque, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.setxattr(path, name, value, flags);
    return error.OperationNotSupported;
}

fn hybridGetxattr(ctx: *anyopaque, path: []const u8, name: []const u8) ![]u8 {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.getxattr(path, name);
    return error.OperationNotSupported;
}

fn hybridListxattr(ctx: *anyopaque, path: []const u8) ![]u8 {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.listxattr(path);
    return error.OperationNotSupported;
}

fn hybridRemovexattr(ctx: *anyopaque, path: []const u8, name: []const u8) !void {
    const self = asCtx(ctx);
    if (routeToRouter(self, path)) return self.router.removexattr(path, name);
    return error.OperationNotSupported;
}

fn hybridLock(ctx: *anyopaque, file: mount_provider.OpenFile, mode: mount_provider.LockMode, wait: bool) !void {
    const self = asCtx(ctx);
    return switch (file) {
        .router => |router_file| self.router.lock(router_file, switch (mode) {
            .shared => .shared,
            .exclusive => .exclusive,
            .unlock => .unlock,
        }, wait),
        .namespace => |namespace_file| self.namespace.lock(namespace_file, @tagName(mode), wait),
    };
}

test "hybrid_mount_provider: pathMatchesMount routes exact and descendant matches" {
    try std.testing.expect(pathMatchesMount("/nodes/local/fs", "/nodes/local/fs"));
    try std.testing.expect(pathMatchesMount("/nodes/local/fs/README.md", "/nodes/local/fs"));
    try std.testing.expect(!pathMatchesMount("/nodes/local", "/nodes/local/fs"));
    try std.testing.expect(!pathMatchesMount("/nodes/local/fsx", "/nodes/local/fs"));
}
