const std = @import("std");
const fs_router = @import("acheron_fs_router");

pub const LockMode = enum {
    shared,
    exclusive,
    unlock,
};

pub const NamespaceHandle = struct {
    handle_id: u64,
    writable: bool,
};

pub const OpenFile = union(enum) {
    router: fs_router.OpenFile,
    namespace: NamespaceHandle,
};

pub const Provider = struct {
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deinit: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) void,
        getattr: *const fn (ctx: *anyopaque, path: []const u8) anyerror![]u8,
        readdir: *const fn (ctx: *anyopaque, path: []const u8, cookie: u64, max_entries: u32) anyerror![]u8,
        statfs: *const fn (ctx: *anyopaque, path: []const u8) anyerror![]u8,
        open: *const fn (ctx: *anyopaque, path: []const u8, flags: u32) anyerror!OpenFile,
        read: *const fn (ctx: *anyopaque, file: OpenFile, off: u64, len: u32) anyerror![]u8,
        release: *const fn (ctx: *anyopaque, file: OpenFile) anyerror!void,
        create: *const fn (ctx: *anyopaque, path: []const u8, mode: u32, flags: u32) anyerror!OpenFile,
        write: *const fn (ctx: *anyopaque, file: OpenFile, off: u64, data: []const u8) anyerror!u32,
        truncate: *const fn (ctx: *anyopaque, path: []const u8, size: u64) anyerror!void,
        unlink: *const fn (ctx: *anyopaque, path: []const u8) anyerror!void,
        mkdir: *const fn (ctx: *anyopaque, path: []const u8) anyerror!void,
        rmdir: *const fn (ctx: *anyopaque, path: []const u8) anyerror!void,
        rename: *const fn (ctx: *anyopaque, old_path: []const u8, new_path: []const u8) anyerror!void,
        symlink: *const fn (ctx: *anyopaque, target: []const u8, link_path: []const u8) anyerror!void,
        setxattr: *const fn (ctx: *anyopaque, path: []const u8, name: []const u8, value: []const u8, flags: u32) anyerror!void,
        getxattr: *const fn (ctx: *anyopaque, path: []const u8, name: []const u8) anyerror![]u8,
        listxattr: *const fn (ctx: *anyopaque, path: []const u8) anyerror![]u8,
        removexattr: *const fn (ctx: *anyopaque, path: []const u8, name: []const u8) anyerror!void,
        lock: *const fn (ctx: *anyopaque, file: OpenFile, mode: LockMode, wait: bool) anyerror!void,
        try_reconcile_endpoints_if_idle: ?*const fn (ctx: *anyopaque, endpoint_configs: []const fs_router.EndpointConfig) anyerror!bool = null,
        try_keepalive_if_idle: ?*const fn (ctx: *anyopaque) anyerror!bool = null,
    };

    pub fn deinit(self: *Provider) void {
        self.vtable.deinit(self.ctx, self.allocator);
        self.* = undefined;
    }

    pub fn getattr(self: *Provider, path: []const u8) ![]u8 {
        return self.vtable.getattr(self.ctx, path);
    }

    pub fn readdir(self: *Provider, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
        return self.vtable.readdir(self.ctx, path, cookie, max_entries);
    }

    pub fn statfs(self: *Provider, path: []const u8) ![]u8 {
        return self.vtable.statfs(self.ctx, path);
    }

    pub fn open(self: *Provider, path: []const u8, flags: u32) !OpenFile {
        return self.vtable.open(self.ctx, path, flags);
    }

    pub fn read(self: *Provider, file: OpenFile, off: u64, len: u32) ![]u8 {
        return self.vtable.read(self.ctx, file, off, len);
    }

    pub fn release(self: *Provider, file: OpenFile) !void {
        try self.vtable.release(self.ctx, file);
    }

    pub fn create(self: *Provider, path: []const u8, mode: u32, flags: u32) !OpenFile {
        return self.vtable.create(self.ctx, path, mode, flags);
    }

    pub fn write(self: *Provider, file: OpenFile, off: u64, data: []const u8) !u32 {
        return self.vtable.write(self.ctx, file, off, data);
    }

    pub fn truncate(self: *Provider, path: []const u8, size: u64) !void {
        try self.vtable.truncate(self.ctx, path, size);
    }

    pub fn unlink(self: *Provider, path: []const u8) !void {
        try self.vtable.unlink(self.ctx, path);
    }

    pub fn mkdir(self: *Provider, path: []const u8) !void {
        try self.vtable.mkdir(self.ctx, path);
    }

    pub fn rmdir(self: *Provider, path: []const u8) !void {
        try self.vtable.rmdir(self.ctx, path);
    }

    pub fn rename(self: *Provider, old_path: []const u8, new_path: []const u8) !void {
        try self.vtable.rename(self.ctx, old_path, new_path);
    }

    pub fn symlink(self: *Provider, target: []const u8, link_path: []const u8) !void {
        try self.vtable.symlink(self.ctx, target, link_path);
    }

    pub fn setxattr(self: *Provider, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
        try self.vtable.setxattr(self.ctx, path, name, value, flags);
    }

    pub fn getxattr(self: *Provider, path: []const u8, name: []const u8) ![]u8 {
        return self.vtable.getxattr(self.ctx, path, name);
    }

    pub fn listxattr(self: *Provider, path: []const u8) ![]u8 {
        return self.vtable.listxattr(self.ctx, path);
    }

    pub fn removexattr(self: *Provider, path: []const u8, name: []const u8) !void {
        try self.vtable.removexattr(self.ctx, path, name);
    }

    pub fn lock(self: *Provider, file: OpenFile, mode: LockMode, wait: bool) !void {
        try self.vtable.lock(self.ctx, file, mode, wait);
    }

    pub fn tryReconcileEndpointsIfIdle(self: *Provider, endpoint_configs: []const fs_router.EndpointConfig) !bool {
        const reconcile = self.vtable.try_reconcile_endpoints_if_idle orelse return false;
        return reconcile(self.ctx, endpoint_configs);
    }

    pub fn tryKeepAliveIfIdle(self: *Provider) !bool {
        const keepalive = self.vtable.try_keepalive_if_idle orelse return false;
        return keepalive(self.ctx);
    }
};

const RouterProviderContext = struct {
    router: *fs_router.Router,
};

pub fn initRouterProvider(allocator: std.mem.Allocator, router: *fs_router.Router) !Provider {
    const ctx = try allocator.create(RouterProviderContext);
    ctx.* = .{ .router = router };
    return .{
        .allocator = allocator,
        .ctx = ctx,
        .vtable = &router_provider_vtable,
    };
}

const router_provider_vtable: Provider.VTable = .{
    .deinit = routerProviderDeinit,
    .getattr = routerProviderGetattr,
    .readdir = routerProviderReaddir,
    .statfs = routerProviderStatfs,
    .open = routerProviderOpen,
    .read = routerProviderRead,
    .release = routerProviderRelease,
    .create = routerProviderCreate,
    .write = routerProviderWrite,
    .truncate = routerProviderTruncate,
    .unlink = routerProviderUnlink,
    .mkdir = routerProviderMkdir,
    .rmdir = routerProviderRmdir,
    .rename = routerProviderRename,
    .symlink = routerProviderSymlink,
    .setxattr = routerProviderSetxattr,
    .getxattr = routerProviderGetxattr,
    .listxattr = routerProviderListxattr,
    .removexattr = routerProviderRemovexattr,
    .lock = routerProviderLock,
    .try_reconcile_endpoints_if_idle = routerProviderTryReconcileEndpointsIfIdle,
};

fn asRouterCtx(ctx: *anyopaque) *RouterProviderContext {
    return @ptrCast(@alignCast(ctx));
}

fn routerProviderDeinit(ctx: *anyopaque, allocator: std.mem.Allocator) void {
    allocator.destroy(asRouterCtx(ctx));
}

fn routerProviderGetattr(ctx: *anyopaque, path: []const u8) ![]u8 {
    return asRouterCtx(ctx).router.getattr(path);
}

fn routerProviderReaddir(ctx: *anyopaque, path: []const u8, cookie: u64, max_entries: u32) ![]u8 {
    return asRouterCtx(ctx).router.readdir(path, cookie, max_entries);
}

fn routerProviderStatfs(ctx: *anyopaque, path: []const u8) ![]u8 {
    return asRouterCtx(ctx).router.statfs(path);
}

fn routerProviderOpen(ctx: *anyopaque, path: []const u8, flags: u32) !OpenFile {
    return .{ .router = try asRouterCtx(ctx).router.open(path, flags) };
}

fn routerProviderRead(ctx: *anyopaque, file: OpenFile, off: u64, len: u32) ![]u8 {
    return asRouterCtx(ctx).router.read(file.router, off, len);
}

fn routerProviderRelease(ctx: *anyopaque, file: OpenFile) !void {
    try asRouterCtx(ctx).router.close(file.router);
}

fn routerProviderCreate(ctx: *anyopaque, path: []const u8, mode: u32, flags: u32) !OpenFile {
    return .{ .router = try asRouterCtx(ctx).router.create(path, mode, flags) };
}

fn routerProviderWrite(ctx: *anyopaque, file: OpenFile, off: u64, data: []const u8) !u32 {
    return asRouterCtx(ctx).router.write(file.router, off, data);
}

fn routerProviderTruncate(ctx: *anyopaque, path: []const u8, size: u64) !void {
    try asRouterCtx(ctx).router.truncate(path, size);
}

fn routerProviderUnlink(ctx: *anyopaque, path: []const u8) !void {
    try asRouterCtx(ctx).router.unlink(path);
}

fn routerProviderMkdir(ctx: *anyopaque, path: []const u8) !void {
    try asRouterCtx(ctx).router.mkdir(path);
}

fn routerProviderRmdir(ctx: *anyopaque, path: []const u8) !void {
    try asRouterCtx(ctx).router.rmdir(path);
}

fn routerProviderRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) !void {
    try asRouterCtx(ctx).router.rename(old_path, new_path);
}

fn routerProviderSymlink(ctx: *anyopaque, target: []const u8, link_path: []const u8) !void {
    try asRouterCtx(ctx).router.symlink(target, link_path);
}

fn routerProviderSetxattr(ctx: *anyopaque, path: []const u8, name: []const u8, value: []const u8, flags: u32) !void {
    try asRouterCtx(ctx).router.setxattr(path, name, value, flags);
}

fn routerProviderGetxattr(ctx: *anyopaque, path: []const u8, name: []const u8) ![]u8 {
    return asRouterCtx(ctx).router.getxattr(path, name);
}

fn routerProviderListxattr(ctx: *anyopaque, path: []const u8) ![]u8 {
    return asRouterCtx(ctx).router.listxattr(path);
}

fn routerProviderRemovexattr(ctx: *anyopaque, path: []const u8, name: []const u8) !void {
    try asRouterCtx(ctx).router.removexattr(path, name);
}

fn routerProviderLock(ctx: *anyopaque, file: OpenFile, mode: LockMode, wait: bool) !void {
    const router_mode: fs_router.LockMode = switch (mode) {
        .shared => .shared,
        .exclusive => .exclusive,
        .unlock => .unlock,
    };
    try asRouterCtx(ctx).router.lock(file.router, router_mode, wait);
}

fn routerProviderTryReconcileEndpointsIfIdle(ctx: *anyopaque, endpoint_configs: []const fs_router.EndpointConfig) !bool {
    try asRouterCtx(ctx).router.reconcileEndpoints(endpoint_configs);
    return true;
}
