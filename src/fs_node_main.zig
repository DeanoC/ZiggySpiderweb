const std = @import("std");
const builtin = @import("builtin");
const fs_node_server = @import("fs_node_server.zig");
const fs_node_ops = @import("fs_node_ops.zig");

const default_state_path = ".spiderweb-fs-node-state.json";
const default_node_name = "spiderweb-fs-node";
const default_control_backoff_ms: u64 = 5_000;
const default_control_backoff_max_ms: u64 = 60_000;
const default_lease_ttl_ms: u64 = 15 * 60 * 1000;
const default_lease_refresh_interval_ms: u64 = 60 * 1000;
const control_reply_timeout_ms: i32 = 45_000;

const PairMode = enum {
    invite,
    request,
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

const ControlConnectOptions = struct {
    url: []const u8,
    auth_token: ?[]const u8 = null,
};

const ControlResult = union(enum) {
    payload_json: []u8,
    remote_error: RemoteError,

    fn deinit(self: *ControlResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .payload_json => |value| allocator.free(value),
            .remote_error => |*err| err.deinit(allocator),
        }
        self.* = undefined;
    }
};

const RemoteError = struct {
    code: []u8,
    message: []u8,

    fn deinit(self: *RemoteError, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
        self.* = undefined;
    }
};

const NodeJoinPayload = struct {
    node_id: []u8,
    node_secret: []u8,
    lease_token: []u8,
    lease_expires_at_ms: i64,
    node_name: ?[]u8 = null,
    fs_url: ?[]u8 = null,

    fn deinit(self: *NodeJoinPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.node_id);
        allocator.free(self.node_secret);
        allocator.free(self.lease_token);
        if (self.node_name) |value| allocator.free(value);
        if (self.fs_url) |value| allocator.free(value);
        self.* = undefined;
    }
};

const NodePairState = struct {
    node_id: ?[]u8 = null,
    node_secret: ?[]u8 = null,
    lease_token: ?[]u8 = null,
    lease_expires_at_ms: i64 = 0,
    request_id: ?[]u8 = null,
    node_name: ?[]u8 = null,
    fs_url: ?[]u8 = null,

    fn deinit(self: *NodePairState, allocator: std.mem.Allocator) void {
        if (self.node_id) |value| allocator.free(value);
        if (self.node_secret) |value| allocator.free(value);
        if (self.lease_token) |value| allocator.free(value);
        if (self.request_id) |value| allocator.free(value);
        if (self.node_name) |value| allocator.free(value);
        if (self.fs_url) |value| allocator.free(value);
        self.* = .{};
    }

    fn isPaired(self: *const NodePairState) bool {
        return self.node_id != null and self.node_secret != null;
    }

    fn clearRequest(self: *NodePairState, allocator: std.mem.Allocator) void {
        if (self.request_id) |value| allocator.free(value);
        self.request_id = null;
    }

    fn setRequestId(self: *NodePairState, allocator: std.mem.Allocator, request_id: []const u8) !void {
        self.clearRequest(allocator);
        self.request_id = try allocator.dupe(u8, request_id);
    }

    fn setFromJoin(self: *NodePairState, allocator: std.mem.Allocator, join: NodeJoinPayload) !void {
        if (self.node_id) |value| allocator.free(value);
        if (self.node_secret) |value| allocator.free(value);
        if (self.lease_token) |value| allocator.free(value);
        if (self.node_name) |value| allocator.free(value);
        if (self.fs_url) |value| allocator.free(value);

        self.node_id = join.node_id;
        self.node_secret = join.node_secret;
        self.lease_token = join.lease_token;
        self.lease_expires_at_ms = join.lease_expires_at_ms;
        self.node_name = if (join.node_name) |value| value else null;
        self.fs_url = if (join.fs_url) |value| value else null;
        self.clearRequest(allocator);
    }

    fn adoptFrom(self: *NodePairState, allocator: std.mem.Allocator, incoming: *NodePairState) void {
        self.deinit(allocator);
        self.* = incoming.*;
        incoming.* = .{};
    }
};

const ControlPairingOptions = struct {
    connect: ControlConnectOptions,
    pair_mode: PairMode,
    invite_token: ?[]const u8,
    operator_token: ?[]const u8,
    node_name: []const u8,
    fs_url: []const u8,
    lease_ttl_ms: u64,
    state_path: []const u8,
    reconnect_backoff_ms: u64,
    reconnect_backoff_max_ms: u64,
};

const LeaseRefreshContext = struct {
    allocator: std.mem.Allocator,
    connect: ControlConnectOptions,
    state_path: []u8,
    fs_url: []u8,
    lease_ttl_ms: u64,
    refresh_interval_ms: u64,
    reconnect_backoff_ms: u64,
    reconnect_backoff_max_ms: u64,
    stop_mutex: std.Thread.Mutex = .{},
    stop: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        connect: ControlConnectOptions,
        state_path: []const u8,
        fs_url: []const u8,
        lease_ttl_ms: u64,
        refresh_interval_ms: u64,
        reconnect_backoff_ms: u64,
        reconnect_backoff_max_ms: u64,
    ) !LeaseRefreshContext {
        return .{
            .allocator = allocator,
            .connect = .{
                .url = try allocator.dupe(u8, connect.url),
                .auth_token = if (connect.auth_token) |token| try allocator.dupe(u8, token) else null,
            },
            .state_path = try allocator.dupe(u8, state_path),
            .fs_url = try allocator.dupe(u8, fs_url),
            .lease_ttl_ms = lease_ttl_ms,
            .refresh_interval_ms = refresh_interval_ms,
            .reconnect_backoff_ms = reconnect_backoff_ms,
            .reconnect_backoff_max_ms = reconnect_backoff_max_ms,
        };
    }

    fn deinit(self: *LeaseRefreshContext) void {
        self.allocator.free(self.connect.url);
        if (self.connect.auth_token) |value| self.allocator.free(value);
        self.allocator.free(self.state_path);
        self.allocator.free(self.fs_url);
        self.* = undefined;
    }

    fn requestStop(self: *LeaseRefreshContext) void {
        self.stop_mutex.lock();
        defer self.stop_mutex.unlock();
        self.stop = true;
    }

    fn shouldStop(self: *LeaseRefreshContext) bool {
        self.stop_mutex.lock();
        defer self.stop_mutex.unlock();
        return self.stop;
    }

    fn sleepWithStop(self: *LeaseRefreshContext, total_ms: u64) bool {
        if (total_ms == 0) return !self.shouldStop();

        var elapsed: u64 = 0;
        while (elapsed < total_ms) {
            if (self.shouldStop()) return false;
            const chunk_ms: u64 = @min(@as(u64, 250), total_ms - elapsed);
            std.Thread.sleep(chunk_ms * std.time.ns_per_ms);
            elapsed += chunk_ms;
        }

        return !self.shouldStop();
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var bind_addr: []const u8 = "127.0.0.1";
    var port: u16 = 18891;
    var exports = std.ArrayListUnmanaged(fs_node_ops.ExportSpec){};
    defer exports.deinit(allocator);
    var auth_token: ?[]const u8 = null;
    var control_url: ?[]const u8 = null;
    var control_auth_token: ?[]const u8 = null;
    var operator_token: ?[]const u8 = null;
    var pair_mode: PairMode = .request;
    var pair_mode_explicit = false;
    var invite_token: ?[]const u8 = null;
    var node_name: []const u8 = default_node_name;
    var advertised_fs_url: ?[]const u8 = null;
    var state_path: []const u8 = default_state_path;
    var lease_ttl_ms: u64 = default_lease_ttl_ms;
    var refresh_interval_ms: u64 = default_lease_refresh_interval_ms;
    var reconnect_backoff_ms: u64 = default_control_backoff_ms;
    var reconnect_backoff_max_ms: u64 = default_control_backoff_max_ms;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            bind_addr = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--export")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            const spec = parseExportFlag(args[i]) catch return error.InvalidArguments;
            try exports.append(allocator, spec);
        } else if (std.mem.eql(u8, arg, "--auth-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            auth_token = args[i];
        } else if (std.mem.eql(u8, arg, "--control-url")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            control_url = args[i];
        } else if (std.mem.eql(u8, arg, "--control-auth-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            control_auth_token = args[i];
        } else if (std.mem.eql(u8, arg, "--operator-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            operator_token = args[i];
        } else if (std.mem.eql(u8, arg, "--pair-mode")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            pair_mode = parsePairMode(args[i]) orelse return error.InvalidArguments;
            pair_mode_explicit = true;
        } else if (std.mem.eql(u8, arg, "--invite-token")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            invite_token = args[i];
        } else if (std.mem.eql(u8, arg, "--node-name")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            node_name = args[i];
        } else if (std.mem.eql(u8, arg, "--fs-url")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            advertised_fs_url = args[i];
        } else if (std.mem.eql(u8, arg, "--state-file")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            state_path = args[i];
        } else if (std.mem.eql(u8, arg, "--lease-ttl-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            lease_ttl_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--refresh-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            refresh_interval_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--reconnect-backoff-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            reconnect_backoff_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--reconnect-backoff-max-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArguments;
            reconnect_backoff_max_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            return;
        } else {
            std.log.err("unknown argument: {s}", .{arg});
            try printHelp();
            return error.InvalidArguments;
        }
    }

    if (!pair_mode_explicit and invite_token != null) {
        pair_mode = .invite;
    }

    const effective_fs_url = if (advertised_fs_url) |value|
        value
    else
        try std.fmt.allocPrint(allocator, "ws://{s}:{d}/v2/fs", .{ bind_addr, port });
    defer if (advertised_fs_url == null) allocator.free(effective_fs_url);

    if (control_url) |control_url_value| {
        if (control_auth_token == null) {
            const from_env = std.process.getEnvVarOwned(allocator, "SPIDERWEB_AUTH_TOKEN") catch |err| switch (err) {
                error.EnvironmentVariableNotFound => null,
                else => return err,
            };
            if (from_env) |raw| {
                const trimmed = std.mem.trim(u8, raw, " \t\r\n");
                if (trimmed.len > 0) {
                    control_auth_token = try allocator.dupe(u8, trimmed);
                }
                allocator.free(raw);
            }
        }

        var state = try loadNodePairState(allocator, state_path);
        defer state.deinit(allocator);
        if (!state.isPaired()) {
            const pairing_opts = ControlPairingOptions{
                .connect = .{
                    .url = control_url_value,
                    .auth_token = control_auth_token,
                },
                .pair_mode = pair_mode,
                .invite_token = invite_token,
                .operator_token = operator_token,
                .node_name = node_name,
                .fs_url = effective_fs_url,
                .lease_ttl_ms = lease_ttl_ms,
                .state_path = state_path,
                .reconnect_backoff_ms = reconnect_backoff_ms,
                .reconnect_backoff_max_ms = reconnect_backoff_max_ms,
            };
            try pairNodeUntilCredentials(allocator, pairing_opts, &state);
        }

        if (!state.isPaired()) {
            std.log.err("control pairing did not produce node credentials", .{});
            return error.PairingFailed;
        }

        if (auth_token) |manual_auth| {
            if (state.node_secret) |secret| {
                if (!std.mem.eql(u8, manual_auth, secret)) {
                    std.log.warn("--auth-token differs from paired node_secret; node_secret should be used for control-routed mounts", .{});
                }
            }
        } else {
            auth_token = state.node_secret;
        }

        if (auth_token) |token| {
            std.log.info("FS node session auth enabled", .{});
            if (state.node_secret) |secret| {
                if (!std.mem.eql(u8, token, secret)) {
                    std.log.warn("fs auth token does not match paired node secret", .{});
                }
            }
        }

        var refresh_ctx = try allocator.create(LeaseRefreshContext);
        defer allocator.destroy(refresh_ctx);
        refresh_ctx.* = try LeaseRefreshContext.init(
            allocator,
            .{
                .url = control_url_value,
                .auth_token = control_auth_token,
            },
            state_path,
            effective_fs_url,
            lease_ttl_ms,
            refresh_interval_ms,
            reconnect_backoff_ms,
            reconnect_backoff_max_ms,
        );
        defer refresh_ctx.deinit();

        var refresh_thread = try std.Thread.spawn(.{}, leaseRefreshThreadMain, .{refresh_ctx});
        defer {
            refresh_ctx.requestStop();
            refresh_thread.join();
        }

        std.log.info("Starting spiderweb-fs-node on {s}:{d}", .{ bind_addr, port });
        std.log.info("Control pairing enabled via {s} ({s})", .{ control_url_value, @tagName(pair_mode) });
        std.log.info("Advertised FS URL: {s}", .{effective_fs_url});
        if (exports.items.len == 0) {
            std.log.info("No exports configured via CLI; using default export name='work' path='.' rw", .{});
        } else {
            for (exports.items) |spec| {
                std.log.info("Export {s} => {s} ({s})", .{ spec.name, spec.path, if (spec.ro) "ro" else "rw" });
            }
        }

        try fs_node_server.run(allocator, bind_addr, port, exports.items, auth_token);
        return;
    }

    if (auth_token == null) {
        const from_env = std.process.getEnvVarOwned(allocator, "SPIDERWEB_FS_NODE_AUTH_TOKEN") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        if (from_env) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len > 0) {
                auth_token = try allocator.dupe(u8, trimmed);
            }
            allocator.free(raw);
        }
    }

    std.log.info("Starting spiderweb-fs-node on {s}:{d}", .{ bind_addr, port });
    if (auth_token != null) {
        std.log.info("FS node session auth enabled", .{});
    }
    if (exports.items.len == 0) {
        std.log.info("No exports configured via CLI; using default export name='work' path='.' rw", .{});
    } else {
        for (exports.items) |spec| {
            std.log.info("Export {s} => {s} ({s})", .{ spec.name, spec.path, if (spec.ro) "ro" else "rw" });
        }
    }

    try fs_node_server.run(allocator, bind_addr, port, exports.items, auth_token);
}

fn parsePairMode(raw: []const u8) ?PairMode {
    if (std.mem.eql(u8, raw, "invite")) return .invite;
    if (std.mem.eql(u8, raw, "request")) return .request;
    return null;
}

fn pairNodeUntilCredentials(
    allocator: std.mem.Allocator,
    opts: ControlPairingOptions,
    state: *NodePairState,
) !void {
    var attempts: u32 = 0;

    while (!state.isPaired()) {
        var from_disk = try loadNodePairState(allocator, opts.state_path);
        defer from_disk.deinit(allocator);

        if (from_disk.isPaired()) {
            state.adoptFrom(allocator, &from_disk);
            break;
        }

        if (from_disk.request_id != null and state.request_id == null) {
            state.clearRequest(allocator);
            if (from_disk.request_id) |value| {
                state.request_id = try allocator.dupe(u8, value);
            }
        }

        try attemptPairingOnce(allocator, opts, state);
        try saveNodePairState(allocator, opts.state_path, state);

        if (state.isPaired()) break;

        const wait_ms = computeBackoff(
            opts.reconnect_backoff_ms,
            opts.reconnect_backoff_max_ms,
            attempts,
        );
        attempts +%= 1;
        std.log.info("node pairing pending; retrying in {d} ms", .{wait_ms});
        std.Thread.sleep(wait_ms * std.time.ns_per_ms);
    }

    try saveNodePairState(allocator, opts.state_path, state);
}

fn attemptPairingOnce(
    allocator: std.mem.Allocator,
    opts: ControlPairingOptions,
    state: *NodePairState,
) !void {
    if (state.isPaired()) return;

    switch (opts.pair_mode) {
        .invite => {
            const token = opts.invite_token orelse return error.InvalidArguments;
            var payload = std.ArrayListUnmanaged(u8){};
            defer payload.deinit(allocator);
            const escaped_invite = try jsonEscape(allocator, token);
            defer allocator.free(escaped_invite);
            const escaped_name = try jsonEscape(allocator, opts.node_name);
            defer allocator.free(escaped_name);
            const escaped_fs_url = try jsonEscape(allocator, opts.fs_url);
            defer allocator.free(escaped_fs_url);
            try payload.writer(allocator).print(
                "{{\"invite_token\":\"{s}\",\"node_name\":\"{s}\",\"fs_url\":\"{s}\",\"lease_ttl_ms\":{d}}}",
                .{ escaped_invite, escaped_name, escaped_fs_url, opts.lease_ttl_ms },
            );

            var result = requestControlPayload(
                allocator,
                opts.connect,
                "control.node_join",
                payload.items,
            ) catch |err| {
                std.log.warn("node invite join request failed: {s}", .{@errorName(err)});
                return;
            };
            defer result.deinit(allocator);

            switch (result) {
                .payload_json => |payload_json| {
                    var joined = parseNodeJoinPayload(allocator, payload_json) catch |err| {
                        std.log.warn("node invite join payload invalid: {s}", .{@errorName(err)});
                        return;
                    };
                    errdefer joined.deinit(allocator);
                    try state.setFromJoin(allocator, joined);
                    std.log.info("node paired via invite: {s}", .{state.node_id.?});
                },
                .remote_error => |remote| {
                    std.log.warn(
                        "node invite join rejected: code={s} message={s}",
                        .{ remote.code, remote.message },
                    );
                },
            }
        },
        .request => {
            if (state.request_id == null) {
                var req_payload = std.ArrayListUnmanaged(u8){};
                defer req_payload.deinit(allocator);
                const escaped_name = try jsonEscape(allocator, opts.node_name);
                defer allocator.free(escaped_name);
                const escaped_fs_url = try jsonEscape(allocator, opts.fs_url);
                defer allocator.free(escaped_fs_url);
                const escaped_os = try jsonEscape(allocator, @tagName(builtin.os.tag));
                defer allocator.free(escaped_os);
                const escaped_arch = try jsonEscape(allocator, @tagName(builtin.cpu.arch));
                defer allocator.free(escaped_arch);

                try req_payload.writer(allocator).print(
                    "{{\"node_name\":\"{s}\",\"fs_url\":\"{s}\",\"platform\":{{\"os\":\"{s}\",\"arch\":\"{s}\",\"runtime_kind\":\"native\"}}}}",
                    .{ escaped_name, escaped_fs_url, escaped_os, escaped_arch },
                );

                var result = requestControlPayload(
                    allocator,
                    opts.connect,
                    "control.node_join_request",
                    req_payload.items,
                ) catch |err| {
                    std.log.warn("node join-request failed: {s}", .{@errorName(err)});
                    return;
                };
                defer result.deinit(allocator);

                switch (result) {
                    .payload_json => |payload_json| {
                        const request_id = parsePendingRequestId(allocator, payload_json) catch |err| {
                            std.log.warn("node join-request response invalid: {s}", .{@errorName(err)});
                            return;
                        };
                        defer allocator.free(request_id);
                        try state.setRequestId(allocator, request_id);
                        std.log.info("node join request submitted: {s}", .{request_id});
                    },
                    .remote_error => |remote| {
                        std.log.warn(
                            "node join-request rejected: code={s} message={s}",
                            .{ remote.code, remote.message },
                        );
                        return;
                    },
                }
            }

            const request_id = state.request_id orelse return;
            var approve_payload = std.ArrayListUnmanaged(u8){};
            defer approve_payload.deinit(allocator);
            const escaped_request = try jsonEscape(allocator, request_id);
            defer allocator.free(escaped_request);
            try approve_payload.writer(allocator).print(
                "{{\"request_id\":\"{s}\",\"lease_ttl_ms\":{d}",
                .{ escaped_request, opts.lease_ttl_ms },
            );
            if (opts.operator_token) |token| {
                const escaped_token = try jsonEscape(allocator, token);
                defer allocator.free(escaped_token);
                try approve_payload.writer(allocator).print(",\"operator_token\":\"{s}\"", .{escaped_token});
            }
            try approve_payload.append(allocator, '}');

            var approve_result = requestControlPayload(
                allocator,
                opts.connect,
                "control.node_join_approve",
                approve_payload.items,
            ) catch |err| {
                std.log.warn("node join approval attempt failed: {s}", .{@errorName(err)});
                return;
            };
            defer approve_result.deinit(allocator);

            switch (approve_result) {
                .payload_json => |payload_json| {
                    var joined = parseNodeJoinPayload(allocator, payload_json) catch |err| {
                        std.log.warn("node join approval payload invalid: {s}", .{@errorName(err)});
                        return;
                    };
                    errdefer joined.deinit(allocator);
                    try state.setFromJoin(allocator, joined);
                    std.log.info("node paired via join-request approval: {s}", .{state.node_id.?});
                },
                .remote_error => |remote| {
                    if (std.mem.eql(u8, remote.code, "pending_join_not_found")) {
                        state.clearRequest(allocator);
                    }
                    std.log.info(
                        "node join approval pending: code={s} message={s}",
                        .{ remote.code, remote.message },
                    );
                },
            }
        },
    }
}

fn leaseRefreshThreadMain(ctx: *LeaseRefreshContext) void {
    var failures: u32 = 0;

    while (true) {
        const wait_ms = if (failures == 0)
            ctx.refresh_interval_ms
        else
            computeBackoff(ctx.reconnect_backoff_ms, ctx.reconnect_backoff_max_ms, failures - 1);

        if (!ctx.sleepWithStop(wait_ms)) return;

        var state = loadNodePairState(ctx.allocator, ctx.state_path) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh: failed to read node state: {s}", .{@errorName(err)});
            continue;
        };
        defer state.deinit(ctx.allocator);

        if (!state.isPaired()) {
            failures = 0;
            continue;
        }

        const node_id = state.node_id orelse continue;
        const node_secret = state.node_secret orelse continue;

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(ctx.allocator);
        const escaped_node_id = jsonEscape(ctx.allocator, node_id) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh: escape node_id failed: {s}", .{@errorName(err)});
            continue;
        };
        defer ctx.allocator.free(escaped_node_id);
        const escaped_node_secret = jsonEscape(ctx.allocator, node_secret) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh: escape node_secret failed: {s}", .{@errorName(err)});
            continue;
        };
        defer ctx.allocator.free(escaped_node_secret);
        const escaped_fs_url = jsonEscape(ctx.allocator, ctx.fs_url) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh: escape fs_url failed: {s}", .{@errorName(err)});
            continue;
        };
        defer ctx.allocator.free(escaped_fs_url);

        payload.writer(ctx.allocator).print(
            "{{\"node_id\":\"{s}\",\"node_secret\":\"{s}\",\"fs_url\":\"{s}\",\"lease_ttl_ms\":{d}}}",
            .{ escaped_node_id, escaped_node_secret, escaped_fs_url, ctx.lease_ttl_ms },
        ) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh: build payload failed: {s}", .{@errorName(err)});
            continue;
        };

        var result = requestControlPayload(
            ctx.allocator,
            ctx.connect,
            "control.node_lease_refresh",
            payload.items,
        ) catch |err| {
            failures +%= 1;
            std.log.warn("lease refresh RPC failed: {s}", .{@errorName(err)});
            continue;
        };
        defer result.deinit(ctx.allocator);

        switch (result) {
            .payload_json => |payload_json| {
                var joined = parseNodeJoinPayload(ctx.allocator, payload_json) catch |err| {
                    failures +%= 1;
                    std.log.warn("lease refresh payload invalid: {s}", .{@errorName(err)});
                    continue;
                };
                errdefer joined.deinit(ctx.allocator);

                tryApplyLeaseRefresh(ctx.allocator, ctx.state_path, &state, joined) catch |err| {
                    failures +%= 1;
                    std.log.warn("lease refresh state update failed: {s}", .{@errorName(err)});
                    continue;
                };

                failures = 0;
                std.log.debug("node lease refreshed: node={s} lease_expires_at_ms={d}", .{ state.node_id.?, state.lease_expires_at_ms });
            },
            .remote_error => |remote| {
                failures +%= 1;
                std.log.warn("lease refresh rejected: code={s} message={s}", .{ remote.code, remote.message });
            },
        }
    }
}

fn tryApplyLeaseRefresh(
    allocator: std.mem.Allocator,
    state_path: []const u8,
    state: *NodePairState,
    join: NodeJoinPayload,
) !void {
    errdefer {
        var cleanup = join;
        cleanup.deinit(allocator);
    }

    const old_id = state.node_id;
    const old_secret = state.node_secret;
    if (old_id == null or old_secret == null) {
        try state.setFromJoin(allocator, join);
        try saveNodePairState(allocator, state_path, state);
        return;
    }

    if (!std.mem.eql(u8, old_id.?, join.node_id) or !std.mem.eql(u8, old_secret.?, join.node_secret)) {
        std.log.warn("lease refresh returned mismatched node identity; ignoring update", .{});
        return;
    }

    try state.setFromJoin(allocator, join);
    try saveNodePairState(allocator, state_path, state);
}

fn computeBackoff(base_ms: u64, max_ms: u64, attempt: u32) u64 {
    const capped_attempt: u6 = @intCast(@min(attempt, 20));
    const shifted = base_ms << capped_attempt;
    if (shifted < base_ms) return max_ms;
    return @min(shifted, max_ms);
}

fn requestControlPayload(
    allocator: std.mem.Allocator,
    connect: ControlConnectOptions,
    op_type: []const u8,
    payload_json: []const u8,
) !ControlResult {
    const parsed_url = try parseWsUrlWithDefaultPath(connect.url, "/");
    var stream = try std.net.tcpConnectToHost(allocator, parsed_url.host, parsed_url.port);
    defer stream.close();

    try performClientHandshake(
        allocator,
        &stream,
        parsed_url.host,
        parsed_url.port,
        parsed_url.path,
        connect.auth_token,
    );
    try negotiateControlVersion(allocator, &stream, "fs-node-version");

    try writeClientTextFrameMasked(
        allocator,
        &stream,
        "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"fs-node-connect\",\"payload\":{}}",
    );
    const connect_envelope = try readControlEnvelopeFor(
        allocator,
        &stream,
        "fs-node-connect",
        control_reply_timeout_ms,
    );
    defer allocator.free(connect_envelope);
    try ensureEnvelopeType(allocator, connect_envelope, "control.connect_ack");

    const escaped_type = try jsonEscape(allocator, op_type);
    defer allocator.free(escaped_type);
    const message = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"{s}\",\"id\":\"fs-node-op\",\"payload\":{s}}}",
        .{ escaped_type, payload_json },
    );
    defer allocator.free(message);

    try writeClientTextFrameMasked(allocator, &stream, message);
    const envelope = try readControlEnvelopeFor(
        allocator,
        &stream,
        "fs-node-op",
        control_reply_timeout_ms,
    );
    defer allocator.free(envelope);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, envelope, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidControlResponse;

    const msg_type_val = parsed.value.object.get("type") orelse return error.InvalidControlResponse;
    if (msg_type_val != .string) return error.InvalidControlResponse;

    if (std.mem.eql(u8, msg_type_val.string, "control.error")) {
        const err_val = parsed.value.object.get("error") orelse return error.InvalidControlResponse;
        if (err_val != .object) return error.InvalidControlResponse;
        const code_val = err_val.object.get("code") orelse return error.InvalidControlResponse;
        if (code_val != .string or code_val.string.len == 0) return error.InvalidControlResponse;
        const message_val = err_val.object.get("message") orelse return error.InvalidControlResponse;
        if (message_val != .string) return error.InvalidControlResponse;
        return .{
            .remote_error = .{
                .code = try allocator.dupe(u8, code_val.string),
                .message = try allocator.dupe(u8, message_val.string),
            },
        };
    }

    if (!std.mem.eql(u8, msg_type_val.string, op_type)) return error.UnexpectedControlResponse;

    const payload_val = parsed.value.object.get("payload") orelse return .{ .payload_json = try allocator.dupe(u8, "{}") };
    return .{ .payload_json = try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(payload_val, .{})}) };
}

fn ensureEnvelopeType(allocator: std.mem.Allocator, envelope_json: []const u8, expected_type: []const u8) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, envelope_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidControlResponse;

    const msg_type_val = parsed.value.object.get("type") orelse return error.InvalidControlResponse;
    if (msg_type_val != .string) return error.InvalidControlResponse;

    if (std.mem.eql(u8, msg_type_val.string, expected_type)) return;

    if (std.mem.eql(u8, msg_type_val.string, "control.error")) {
        const err_val = parsed.value.object.get("error") orelse return error.ControlRequestFailed;
        if (err_val == .object) {
            const code = if (err_val.object.get("code")) |value| if (value == .string) value.string else "unknown" else "unknown";
            const message = if (err_val.object.get("message")) |value| if (value == .string) value.string else "control.error" else "control.error";
            std.log.warn("control operation rejected during handshake: code={s} message={s}", .{ code, message });
        }
        return error.ControlRequestFailed;
    }

    return error.UnexpectedControlResponse;
}

fn parseNodeJoinPayload(allocator: std.mem.Allocator, payload_json: []const u8) !NodeJoinPayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;

    const node_id = try dupRequiredString(allocator, parsed.value.object, "node_id");
    errdefer allocator.free(node_id);
    const node_secret = try dupRequiredString(allocator, parsed.value.object, "node_secret");
    errdefer allocator.free(node_secret);
    const lease_token = try dupRequiredString(allocator, parsed.value.object, "lease_token");
    errdefer allocator.free(lease_token);
    const lease_expires_at_ms = getOptionalI64(parsed.value.object, "lease_expires_at_ms", 0) catch 0;

    return .{
        .node_id = node_id,
        .node_secret = node_secret,
        .lease_token = lease_token,
        .lease_expires_at_ms = lease_expires_at_ms,
        .node_name = try dupOptionalString(allocator, parsed.value.object, "node_name"),
        .fs_url = try dupOptionalString(allocator, parsed.value.object, "fs_url"),
    };
}

fn parsePendingRequestId(allocator: std.mem.Allocator, payload_json: []const u8) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return dupRequiredString(allocator, parsed.value.object, "request_id");
}

fn loadNodePairState(allocator: std.mem.Allocator, state_path: []const u8) !NodePairState {
    const raw = std.fs.cwd().readFileAlloc(allocator, state_path, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer allocator.free(raw);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidStateFile;

    var state = NodePairState{};
    errdefer state.deinit(allocator);

    state.node_id = try dupOptionalNullableString(allocator, parsed.value.object, "node_id");
    state.node_secret = try dupOptionalNullableString(allocator, parsed.value.object, "node_secret");
    state.lease_token = try dupOptionalNullableString(allocator, parsed.value.object, "lease_token");
    state.request_id = try dupOptionalNullableString(allocator, parsed.value.object, "request_id");
    state.node_name = try dupOptionalNullableString(allocator, parsed.value.object, "node_name");
    state.fs_url = try dupOptionalNullableString(allocator, parsed.value.object, "fs_url");
    state.lease_expires_at_ms = getOptionalI64(parsed.value.object, "lease_expires_at_ms", 0) catch 0;

    return state;
}

fn saveNodePairState(allocator: std.mem.Allocator, state_path: []const u8, state: *const NodePairState) !void {
    try ensureParentPathExists(state_path);

    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"schema\":1");
    try appendOptionalJsonStringField(allocator, &out, "node_id", state.node_id);
    try appendOptionalJsonStringField(allocator, &out, "node_secret", state.node_secret);
    try appendOptionalJsonStringField(allocator, &out, "lease_token", state.lease_token);
    try out.writer(allocator).print(",\"lease_expires_at_ms\":{d}", .{state.lease_expires_at_ms});
    try appendOptionalJsonStringField(allocator, &out, "request_id", state.request_id);
    try appendOptionalJsonStringField(allocator, &out, "node_name", state.node_name);
    try appendOptionalJsonStringField(allocator, &out, "fs_url", state.fs_url);
    try out.append(allocator, '}');

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{state_path});
    defer allocator.free(tmp_path);

    try std.fs.cwd().writeFile(.{ .sub_path = tmp_path, .data = out.items });
    try std.fs.cwd().rename(tmp_path, state_path);
}

fn appendOptionalJsonStringField(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    key: []const u8,
    value: ?[]const u8,
) !void {
    if (value) |raw| {
        const escaped = try jsonEscape(allocator, raw);
        defer allocator.free(escaped);
        try out.writer(allocator).print(",\"{s}\":\"{s}\"", .{ key, escaped });
        return;
    }
    try out.writer(allocator).print(",\"{s}\":null", .{key});
}

fn ensureParentPathExists(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0) return;

    if (std.fs.path.isAbsolute(parent)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        const relative = std.mem.trimLeft(u8, parent, "/");
        if (relative.len == 0) return;
        try root.makePath(relative);
        return;
    }

    try std.fs.cwd().makePath(parent);
}

fn dupRequiredString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, name: []const u8) ![]u8 {
    const value = obj.get(name) orelse return error.MissingField;
    if (value != .string or value.string.len == 0) return error.InvalidPayload;
    return allocator.dupe(u8, value.string);
}

fn dupOptionalString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, name: []const u8) !?[]u8 {
    const value = obj.get(name) orelse return null;
    if (value == .null) return null;
    if (value != .string) return error.InvalidPayload;
    const copy = try allocator.dupe(u8, value.string);
    return @as(?[]u8, copy);
}

fn dupOptionalNullableString(allocator: std.mem.Allocator, obj: std.json.ObjectMap, name: []const u8) !?[]u8 {
    const value = obj.get(name) orelse return null;
    if (value == .null) return null;
    if (value != .string) return error.InvalidPayload;
    const copy = try allocator.dupe(u8, value.string);
    return @as(?[]u8, copy);
}

fn getOptionalI64(obj: std.json.ObjectMap, name: []const u8, default_value: i64) !i64 {
    const value = obj.get(name) orelse return default_value;
    if (value != .integer) return error.InvalidPayload;
    return value.integer;
}

fn parseExportFlag(raw: []const u8) !fs_node_ops.ExportSpec {
    const eq_index = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidFormat;
    const name = raw[0..eq_index];
    if (name.len == 0) return error.InvalidFormat;

    const rhs = raw[eq_index + 1 ..];
    if (rhs.len == 0) return error.InvalidFormat;

    var ro = false;
    var path = rhs;
    var gdrive_credential_handle: ?[]const u8 = null;

    while (true) {
        if (std.mem.endsWith(u8, path, ":ro")) {
            ro = true;
            path = path[0 .. path.len - 3];
            continue;
        }
        if (std.mem.endsWith(u8, path, ":rw")) {
            ro = false;
            path = path[0 .. path.len - 3];
            continue;
        }

        const cred_idx = std.mem.lastIndexOf(u8, path, ":cred=") orelse break;
        const handle = path[cred_idx + ":cred=".len ..];
        if (handle.len == 0) return error.InvalidFormat;
        if (std.mem.indexOfScalar(u8, handle, ':') != null) break;
        gdrive_credential_handle = handle;
        path = path[0..cred_idx];
    }

    if (path.len == 0) return error.InvalidFormat;

    return .{
        .name = name,
        .path = path,
        .ro = ro,
        .gdrive_credential_handle = gdrive_credential_handle,
        .desc = null,
    };
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
    auth_token: ?[]const u8,
) !void {
    var nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var encoded_nonce: [std.base64.standard.Encoder.calcSize(nonce.len)]u8 = undefined;
    const key = std.base64.standard.Encoder.encode(&encoded_nonce, &nonce);
    const auth_line = if (auth_token) |token|
        try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}\\r\\n", .{token})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(auth_line);

    const request = try std.fmt.allocPrint(
        allocator,
        "GET {s} HTTP/1.1\\r\\n" ++
            "Host: {s}:{d}\\r\\n" ++
            "Upgrade: websocket\\r\\n" ++
            "Connection: Upgrade\\r\\n" ++
            "Sec-WebSocket-Version: 13\\r\\n" ++
            "Sec-WebSocket-Key: {s}\\r\\n" ++
            "{s}\\r\\n",
        .{ path, host, port, key, auth_line },
    );
    defer allocator.free(request);

    try stream.writeAll(request);

    const response = try readHttpResponse(allocator, stream, 8 * 1024);
    defer allocator.free(response);
    if (std.mem.indexOf(u8, response, " 101 ") == null and std.mem.indexOf(u8, response, " 101\\r\\n") == null) {
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
        if (std.mem.indexOf(u8, out.items, "\\r\\n\\r\\n") != null) {
            return out.toOwnedSlice(allocator);
        }
    }
    return error.ResponseTooLarge;
}

fn negotiateControlVersion(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    request_id: []const u8,
) !void {
    const escaped_request_id = try jsonEscape(allocator, request_id);
    defer allocator.free(escaped_request_id);
    const message = try std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"{s}\",\"payload\":{{\"protocol\":\"unified-v2\"}}}}",
        .{escaped_request_id},
    );
    defer allocator.free(message);

    try writeClientTextFrameMasked(allocator, stream, message);
    const envelope = try readControlEnvelopeFor(allocator, stream, request_id, control_reply_timeout_ms);
    defer allocator.free(envelope);
    try ensureEnvelopeType(allocator, envelope, "control.version_ack");
}

fn readControlEnvelopeFor(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    expected_id: []const u8,
    timeout_ms: i32,
) ![]u8 {
    const deadline_ms = std.time.milliTimestamp() + @as(i64, timeout_ms);

    while (true) {
        const now_ms = std.time.milliTimestamp();
        if (now_ms >= deadline_ms) return error.ControlRequestTimeout;
        const remaining_i64 = deadline_ms - now_ms;
        const remaining_ms: i32 = @intCast(@min(remaining_i64, @as(i64, std.math.maxInt(i32))));
        if (!try waitReadable(stream, remaining_ms)) {
            return error.ControlRequestTimeout;
        }

        var frame = try readServerFrame(allocator, stream, 4 * 1024 * 1024);
        defer frame.deinit(allocator);

        switch (frame.opcode) {
            0x1 => {
                var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frame.payload, .{});
                defer parsed.deinit();
                if (parsed.value != .object) continue;

                const channel = parsed.value.object.get("channel") orelse continue;
                if (channel != .string or !std.mem.eql(u8, channel.string, "control")) continue;

                const msg_id = parsed.value.object.get("id") orelse continue;
                if (msg_id != .string or !std.mem.eql(u8, msg_id.string, expected_id)) continue;

                return allocator.dupe(u8, frame.payload);
            },
            0x8 => return error.ConnectionClosed,
            0x9 => try writeClientPongFrameMasked(allocator, stream, frame.payload),
            0xA => {},
            else => return error.InvalidFrameOpcode,
        }
    }
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

    const masked = try allocator.alloc(u8, payload.len);
    defer allocator.free(masked);
    for (payload, 0..) |byte, idx| {
        masked[idx] = byte ^ mask_key[idx % 4];
    }

    try stream.writeAll(header[0..header_len]);
    if (masked.len > 0) try stream.writeAll(masked);
}

fn readExact(stream: *std.net.Stream, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = try stream.read(out[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    for (input) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (char < 0x20) {
                    try out.writer(allocator).print("\\u00{x:0>2}", .{char});
                } else {
                    try out.append(allocator, char);
                }
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

fn printHelp() !void {
    const help =
        \\spiderweb-fs-node - Distributed filesystem node server / daemon
        \\
        \\Usage:
        \\  spiderweb-fs-node [--bind <addr>] [--port <port>] [--export <name>=<path>[:ro|:rw][:cred=<handle>]] [--auth-token <token>]
        \\                    [--control-url <ws-url> [--control-auth-token <token>] [--pair-mode <invite|request>] [--invite-token <token>]
        \\                     [--operator-token <token>] [--node-name <name>] [--fs-url <ws-url>] [--state-file <path>]
        \\                     [--lease-ttl-ms <ms>] [--refresh-interval-ms <ms>] [--reconnect-backoff-ms <ms>] [--reconnect-backoff-max-ms <ms>]]
        \\
        \\Examples:
        \\  spiderweb-fs-node --export work=.:rw
        \\  spiderweb-fs-node --bind 0.0.0.0 --port 18891 --export repo=/home/user/repo:ro
        \\  spiderweb-fs-node --export cloud=drive:root:ro:cred=gdrive.team
        \\  spiderweb-fs-node --auth-token my-node-session-token
        \\  spiderweb-fs-node --control-url ws://127.0.0.1:18790/ --pair-mode invite --invite-token invite-abc --node-name clawz --fs-url ws://10.0.0.8:18891/v2/fs
        \\  spiderweb-fs-node --control-url ws://127.0.0.1:18790/ --pair-mode request --node-name edge-1 --state-file ./node-state.json
        \\  (control auth token can come from SPIDERWEB_AUTH_TOKEN when --control-url is used)
        \\  (standalone fs auth token can come from SPIDERWEB_FS_NODE_AUTH_TOKEN when --control-url is not used)
        \\
    ;
    try std.fs.File.stdout().writeAll(help);
}

test "fs_node_main: parsePairMode accepts invite and request" {
    try std.testing.expect(parsePairMode("invite").? == .invite);
    try std.testing.expect(parsePairMode("request").? == .request);
    try std.testing.expect(parsePairMode("other") == null);
}

test "fs_node_main: node pair state save/load roundtrip" {
    const allocator = std.testing.allocator;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const root = try temp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const state_path = try std.fmt.allocPrint(allocator, "{s}/pair-state.json", .{root});
    defer allocator.free(state_path);

    var state = NodePairState{
        .node_id = try allocator.dupe(u8, "node-12"),
        .node_secret = try allocator.dupe(u8, "secret-abc"),
        .lease_token = try allocator.dupe(u8, "lease-xyz"),
        .lease_expires_at_ms = 1739999999999,
        .request_id = try allocator.dupe(u8, "pending-join-2"),
        .node_name = try allocator.dupe(u8, "edge-12"),
        .fs_url = try allocator.dupe(u8, "ws://10.0.0.12:18891/v2/fs"),
    };
    defer state.deinit(allocator);

    try saveNodePairState(allocator, state_path, &state);

    var loaded = try loadNodePairState(allocator, state_path);
    defer loaded.deinit(allocator);

    try std.testing.expect(loaded.isPaired());
    try std.testing.expectEqualStrings("node-12", loaded.node_id.?);
    try std.testing.expectEqualStrings("secret-abc", loaded.node_secret.?);
    try std.testing.expectEqualStrings("lease-xyz", loaded.lease_token.?);
    try std.testing.expectEqual(@as(i64, 1739999999999), loaded.lease_expires_at_ms);
    try std.testing.expectEqualStrings("pending-join-2", loaded.request_id.?);
    try std.testing.expectEqualStrings("edge-12", loaded.node_name.?);
    try std.testing.expectEqualStrings("ws://10.0.0.12:18891/v2/fs", loaded.fs_url.?);
}
