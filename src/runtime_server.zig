const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const agent_runtime = @import("agent_runtime.zig");
const brain_specialization = @import("brain_specialization.zig");
const credential_store = @import("credential_store.zig");
const memory = @import("memory.zig");
const tool_registry = @import("tool_registry.zig");
const ziggy_piai = @import("ziggy-piai");

pub const default_agent_id = "default";
const DEFAULT_BRAIN = "primary";
const INTERNAL_TICK_TIMEOUT_MS: i64 = 5 * 1000;
const MAX_PROVIDER_TOOL_ROUNDS: usize = 8;
const MAX_PROVIDER_TOOL_CALLS_PER_TURN: usize = 32;

const RuntimeServerError = error{
    RuntimeTickTimeout,
    RuntimeJobTimeout,
    RuntimeJobCancelled,
    MissingJobResponse,
    ProviderModelNotFound,
    MissingProviderApiKey,
    ProviderStreamFailed,
    ProviderToolLoopExceeded,
    MissingLtmStoreConfig,
};

const RuntimeOperationClass = enum {
    chat,
    control,
};

const RuntimeQueueJob = struct {
    msg_type: protocol.MessageType,
    request_id: []u8,
    content: ?[]u8,
    action: ?[]u8,

    result_mutex: std.Thread.Mutex = .{},
    result_cond: std.Thread.Condition = .{},
    done: bool = false,
    cancelled: bool = false,
    response: ?[][]u8 = null,
};

const ProviderCompletion = struct {
    assistant_text: []u8,

    fn deinit(self: *ProviderCompletion, allocator: std.mem.Allocator) void {
        allocator.free(self.assistant_text);
        self.* = undefined;
    }
};

const StreamByModelFn = *const fn (
    std.mem.Allocator,
    *std.http.Client,
    *ziggy_piai.api_registry.ApiRegistry,
    ziggy_piai.types.Model,
    ziggy_piai.types.Context,
    ziggy_piai.types.StreamOptions,
    *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void;

var streamByModelFn: StreamByModelFn = ziggy_piai.stream.streamByModel;

const GetEnvApiKeyFn = *const fn (std.mem.Allocator, []const u8) ?[]const u8;
var getEnvApiKeyFn: GetEnvApiKeyFn = ziggy_piai.env_api_keys.getEnvApiKey;

const ProviderRuntime = struct {
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
    default_provider_name: []u8,
    default_model_name: ?[]u8,
    test_only_api_key: ?[]u8,
    base_url: ?[]u8,
    credentials: credential_store.CredentialStore,

    fn init(allocator: std.mem.Allocator, provider_cfg: Config.ProviderConfig) !ProviderRuntime {
        var model_registry = ziggy_piai.models.ModelRegistry.init(allocator);
        errdefer model_registry.deinit();
        try ziggy_piai.models.registerDefaultModels(&model_registry);

        var api_registry = ziggy_piai.api_registry.ApiRegistry.init(allocator);
        errdefer api_registry.deinit();
        try ziggy_piai.providers.register_builtins.registerBuiltInApiProviders(&api_registry);

        var provider = ProviderRuntime{
            .model_registry = model_registry,
            .api_registry = api_registry,
            .http_client = .{ .allocator = allocator },
            .default_provider_name = try allocator.dupe(u8, provider_cfg.name),
            .default_model_name = null,
            .test_only_api_key = null,
            .base_url = null,
            .credentials = credential_store.CredentialStore.init(allocator),
        };
        errdefer provider.deinit(allocator);

        if (provider_cfg.model) |value| provider.default_model_name = try allocator.dupe(u8, value);
        if (builtin.is_test) {
            if (provider_cfg.api_key) |value| provider.test_only_api_key = try allocator.dupe(u8, value);
        }
        if (provider_cfg.base_url) |value| provider.base_url = try allocator.dupe(u8, value);

        return provider;
    }

    fn deinit(self: *ProviderRuntime, allocator: std.mem.Allocator) void {
        self.model_registry.deinit();
        self.api_registry.deinit();
        self.http_client.deinit();
        allocator.free(self.default_provider_name);
        if (self.default_model_name) |value| allocator.free(value);
        if (self.test_only_api_key) |value| allocator.free(value);
        if (self.base_url) |value| allocator.free(value);
    }
};

pub fn deinitResponseFrames(allocator: std.mem.Allocator, frames: [][]u8) void {
    for (frames) |frame| allocator.free(frame);
    allocator.free(frames);
}

pub const RuntimeServer = struct {
    allocator: std.mem.Allocator,
    runtime: agent_runtime.AgentRuntime,
    provider_runtime: ?ProviderRuntime = null,

    runtime_mutex: std.Thread.Mutex = .{},
    queue_mutex: std.Thread.Mutex = .{},
    queue_cond: std.Thread.Condition = .{},
    runtime_queue_max: usize = 128,
    chat_operation_timeout_ms: u64 = 30_000,
    control_operation_timeout_ms: u64 = 5_000,
    runtime_jobs: std.ArrayListUnmanaged(*RuntimeQueueJob) = .{},
    runtime_workers: []std.Thread,
    stopping: bool = false,
    test_ltm_directory: ?[]u8 = null,

    pub fn create(allocator: std.mem.Allocator, agent_id: []const u8, runtime_cfg: Config.RuntimeConfig) !*RuntimeServer {
        return createInternal(allocator, agent_id, runtime_cfg, null);
    }

    pub fn createWithProvider(
        allocator: std.mem.Allocator,
        agent_id: []const u8,
        runtime_cfg: Config.RuntimeConfig,
        provider_cfg: Config.ProviderConfig,
    ) !*RuntimeServer {
        return createInternal(allocator, agent_id, runtime_cfg, provider_cfg);
    }

    fn createInternal(
        allocator: std.mem.Allocator,
        agent_id: []const u8,
        runtime_cfg: Config.RuntimeConfig,
        provider_cfg: ?Config.ProviderConfig,
    ) !*RuntimeServer {
        const worker_count = if (runtime_cfg.runtime_worker_threads == 0) 1 else runtime_cfg.runtime_worker_threads;

        const self = try allocator.create(RuntimeServer);
        errdefer allocator.destroy(self);

        var effective_ltm_directory = runtime_cfg.ltm_directory;
        var effective_ltm_filename = runtime_cfg.ltm_filename;
        var test_ltm_directory: ?[]u8 = null;
        errdefer if (test_ltm_directory) |dir| allocator.free(dir);

        if (effective_ltm_directory.len == 0) {
            if (!builtin.is_test) return RuntimeServerError.MissingLtmStoreConfig;
            test_ltm_directory = try std.fmt.allocPrint(
                allocator,
                ".tmp-runtime-ltm-{s}-{d}",
                .{ agent_id, std.time.nanoTimestamp() },
            );
            effective_ltm_directory = test_ltm_directory.?;
        }
        if (effective_ltm_filename.len == 0) {
            if (!builtin.is_test) return RuntimeServerError.MissingLtmStoreConfig;
            effective_ltm_filename = "runtime-memory.db";
        }

        var provider_runtime: ?ProviderRuntime = null;
        if (provider_cfg) |cfg| {
            provider_runtime = try ProviderRuntime.init(allocator, cfg);
        }
        errdefer if (provider_runtime) |*provider| provider.deinit(allocator);

        self.* = .{
            .allocator = allocator,
            .runtime = try agent_runtime.AgentRuntime.initWithPersistence(
                allocator,
                agent_id,
                &[_][]const u8{"delegate"},
                effective_ltm_directory,
                effective_ltm_filename,
            ),
            .runtime_queue_max = runtime_cfg.runtime_request_queue_max,
            .chat_operation_timeout_ms = runtime_cfg.chat_operation_timeout_ms,
            .control_operation_timeout_ms = runtime_cfg.control_operation_timeout_ms,
            .runtime_workers = try allocator.alloc(std.Thread, worker_count),
            .provider_runtime = provider_runtime,
            .test_ltm_directory = test_ltm_directory,
        };
        errdefer {
            self.runtime.deinit();
            allocator.free(self.runtime_workers);
            if (self.test_ltm_directory) |dir| {
                std.fs.cwd().deleteTree(dir) catch {};
                allocator.free(dir);
                self.test_ltm_directory = null;
            }
        }

        self.runtime.queue_limits = .{
            .inbound_events = runtime_cfg.inbound_queue_max,
            .brain_ticks = runtime_cfg.brain_tick_queue_max,
            .outbound_messages = runtime_cfg.outbound_queue_max,
            .control_events = runtime_cfg.control_queue_max,
        };

        var launched: usize = 0;
        errdefer {
            self.queue_mutex.lock();
            self.stopping = true;
            self.queue_cond.broadcast();
            self.queue_mutex.unlock();

            var i: usize = 0;
            while (i < launched) : (i += 1) {
                self.runtime_workers[i].join();
            }
        }

        while (launched < self.runtime_workers.len) : (launched += 1) {
            self.runtime_workers[launched] = try std.Thread.spawn(.{}, runtimeWorkerMain, .{self});
        }

        return self;
    }

    pub fn destroy(self: *RuntimeServer) void {
        self.queue_mutex.lock();
        self.stopping = true;
        self.queue_cond.broadcast();
        self.queue_mutex.unlock();

        for (self.runtime_workers) |worker| {
            worker.join();
        }

        self.queue_mutex.lock();
        for (self.runtime_jobs.items) |job| {
            self.destroyJob(job);
        }
        self.runtime_jobs.deinit(self.allocator);
        self.queue_mutex.unlock();

        self.allocator.free(self.runtime_workers);
        if (self.provider_runtime) |*provider| provider.deinit(self.allocator);
        self.runtime.deinit();
        if (self.test_ltm_directory) |dir| {
            std.fs.cwd().deleteTree(dir) catch {};
            self.allocator.free(dir);
            self.test_ltm_directory = null;
        }
        self.allocator.destroy(self);
    }

    pub fn handleMessage(self: *RuntimeServer, raw_json: []const u8) ![]u8 {
        const responses = try self.handleMessageFrames(raw_json);
        if (responses.len == 0) {
            self.allocator.free(responses);
            return RuntimeServerError.MissingJobResponse;
        }

        const first = responses[0];
        for (responses[1..]) |frame| self.allocator.free(frame);
        self.allocator.free(responses);
        return first;
    }

    pub fn handleMessageFrames(self: *RuntimeServer, raw_json: []const u8) ![][]u8 {
        var parsed = protocol.parseMessage(self.allocator, raw_json) catch {
            const payload = try protocol.buildErrorWithCode(self.allocator, "unknown", .invalid_envelope, "invalid request envelope");
            return self.wrapSingleFrame(payload);
        };
        defer protocol.deinitParsedMessage(self.allocator, &parsed);

        const request_id = parsed.id orelse "generated";

        switch (parsed.msg_type) {
            .connect => {
                return self.wrapSingleFrame(try protocol.buildConnectAck(self.allocator, request_id));
            },
            .ping => {
                return self.wrapSingleFrame(try protocol.buildPong(self.allocator));
            },
            .session_send => {
                return self.submitRuntimeJobAndAwait(parsed.msg_type, request_id, parsed.content, parsed.action, .chat);
            },
            .agent_control => {
                const operation_class: RuntimeOperationClass = if (isChatLikeControlAction(parsed.action)) .chat else .control;
                return self.submitRuntimeJobAndAwait(
                    parsed.msg_type,
                    request_id,
                    parsed.content,
                    parsed.action,
                    operation_class,
                );
            },
            else => {
                return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                    self.allocator,
                    request_id,
                    .unsupported_message_type,
                    "unsupported message type",
                ));
            },
        }
    }

    fn submitRuntimeJobAndAwait(
        self: *RuntimeServer,
        msg_type: protocol.MessageType,
        request_id: []const u8,
        content: ?[]const u8,
        action: ?[]const u8,
        operation_class: RuntimeOperationClass,
    ) ![][]u8 {
        const job = try self.createJob(msg_type, request_id, content, action);
        errdefer self.destroyJob(job);

        const enqueued = try self.enqueueJob(job);
        if (!enqueued) {
            self.destroyJob(job);
            return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                self.allocator,
                request_id,
                .queue_saturated,
                "runtime request queue saturated",
            ));
        }

        return self.waitForJob(job, operation_class) catch |err| switch (err) {
            RuntimeServerError.RuntimeJobTimeout => {
                return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                    self.allocator,
                    request_id,
                    .runtime_timeout,
                    "runtime operation timeout",
                ));
            },
            RuntimeServerError.MissingJobResponse => {
                self.destroyJob(job);
                return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                    self.allocator,
                    request_id,
                    .execution_failed,
                    "runtime worker did not produce response",
                ));
            },
            else => {
                self.destroyJob(job);
                return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                    self.allocator,
                    request_id,
                    .execution_failed,
                    @errorName(err),
                ));
            },
        };
    }

    fn enqueueJob(self: *RuntimeServer, job: *RuntimeQueueJob) !bool {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        if (self.stopping) return false;
        if (self.runtime_jobs.items.len >= self.runtime_queue_max) return false;

        try self.runtime_jobs.append(self.allocator, job);
        self.queue_cond.signal();
        return true;
    }

    fn waitForJob(self: *RuntimeServer, job: *RuntimeQueueJob, operation_class: RuntimeOperationClass) ![][]u8 {
        const timeout_ns = self.operationTimeoutNs(operation_class);
        const deadline_ns: i128 = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));

        job.result_mutex.lock();

        while (!job.done) {
            const now_ns = std.time.nanoTimestamp();
            if (now_ns >= deadline_ns) {
                job.cancelled = true;
                const removed_from_queue = self.cancelQueuedJob(job);
                if (removed_from_queue) {
                    job.done = true;
                }
                job.result_mutex.unlock();
                if (removed_from_queue) {
                    self.destroyJob(job);
                }
                return RuntimeServerError.RuntimeJobTimeout;
            }

            const remaining_ns: u64 = @intCast(deadline_ns - now_ns);
            job.result_cond.timedWait(&job.result_mutex, remaining_ns) catch |err| switch (err) {
                error.Timeout => continue,
            };
        }

        const response = job.response orelse {
            job.result_mutex.unlock();
            return RuntimeServerError.MissingJobResponse;
        };
        job.response = null;
        job.result_mutex.unlock();
        self.destroyJob(job);
        return response;
    }

    fn cancelQueuedJob(self: *RuntimeServer, job: *RuntimeQueueJob) bool {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        var idx: usize = 0;
        while (idx < self.runtime_jobs.items.len) : (idx += 1) {
            if (self.runtime_jobs.items[idx] == job) {
                _ = self.runtime_jobs.orderedRemove(idx);
                return true;
            }
        }
        return false;
    }

    fn dequeueJob(self: *RuntimeServer) ?*RuntimeQueueJob {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        while (!self.stopping and self.runtime_jobs.items.len == 0) {
            self.queue_cond.wait(&self.queue_mutex);
        }

        if (self.runtime_jobs.items.len == 0) return null;
        return self.runtime_jobs.orderedRemove(0);
    }

    fn runtimeWorkerMain(self: *RuntimeServer) void {
        while (true) {
            const job = self.dequeueJob() orelse return;

            if (self.isJobCancelled(job)) {
                job.result_mutex.lock();
                job.done = true;
                job.result_cond.signal();
                job.result_mutex.unlock();
                self.destroyJob(job);
                continue;
            }

            const response = self.processRuntimeJob(job) catch |err| blk: {
                if (err == RuntimeServerError.RuntimeJobCancelled) break :blk null;

                const payload = protocol.buildErrorWithCode(self.allocator, job.request_id, .execution_failed, @errorName(err)) catch |build_err| {
                    std.log.err("runtime worker failed building error response: {s}", .{@errorName(build_err)});
                    break :blk null;
                };
                break :blk self.wrapSingleFrame(payload) catch |build_err| {
                    self.allocator.free(payload);
                    std.log.err("runtime worker failed wrapping error response: {s}", .{@errorName(build_err)});
                    break :blk null;
                };
            };

            job.result_mutex.lock();
            job.done = true;
            job.response = response;
            const cancelled = job.cancelled;
            job.result_cond.signal();
            job.result_mutex.unlock();

            if (cancelled) {
                if (response) |frames| deinitResponseFrames(self.allocator, frames);
                self.destroyJob(job);
            }
        }
    }

    fn processRuntimeJob(self: *RuntimeServer, job: *RuntimeQueueJob) ![][]u8 {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        if (self.isJobCancelled(job)) return RuntimeServerError.RuntimeJobCancelled;

        switch (job.msg_type) {
            .session_send => {
                const content = job.content orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "session.send requires content",
                    ));
                };
                return self.handleChat(job, job.request_id, content);
            },
            .agent_control => {
                return self.handleControl(job, job.request_id, job.action, job.content);
            },
            else => {
                return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                    self.allocator,
                    job.request_id,
                    .unsupported_message_type,
                    "unsupported runtime job type",
                ));
            },
        }
    }

    fn isJobCancelled(_: *RuntimeServer, job: *RuntimeQueueJob) bool {
        job.result_mutex.lock();
        defer job.result_mutex.unlock();
        return job.cancelled;
    }

    fn createJob(
        self: *RuntimeServer,
        msg_type: protocol.MessageType,
        request_id: []const u8,
        content: ?[]const u8,
        action: ?[]const u8,
    ) !*RuntimeQueueJob {
        const job = try self.allocator.create(RuntimeQueueJob);
        errdefer self.allocator.destroy(job);

        job.* = .{
            .msg_type = msg_type,
            .request_id = try self.allocator.dupe(u8, request_id),
            .content = if (content) |value| try self.allocator.dupe(u8, value) else null,
            .action = if (action) |value| try self.allocator.dupe(u8, value) else null,
        };
        return job;
    }

    fn destroyJob(self: *RuntimeServer, job: *RuntimeQueueJob) void {
        self.allocator.free(job.request_id);
        if (job.content) |owned| self.allocator.free(owned);
        if (job.action) |owned| self.allocator.free(owned);
        if (job.response) |frames| deinitResponseFrames(self.allocator, frames);
        self.allocator.destroy(job);
    }

    fn handleChat(self: *RuntimeServer, job: *RuntimeQueueJob, request_id: []const u8, content: []const u8) ![][]u8 {
        if (self.isJobCancelled(job)) return RuntimeServerError.RuntimeJobCancelled;

        self.runtime.appendMessageMemory(DEFAULT_BRAIN, "user", content) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        var provider_completion = if (self.provider_runtime != null)
            self.completeWithProvider(job, DEFAULT_BRAIN) catch |err| return self.wrapRuntimeErrorResponse(request_id, err)
        else
            ProviderCompletion{
                .assistant_text = try self.allocator.dupe(u8, content),
            };
        defer provider_completion.deinit(self.allocator);

        if (self.isJobCancelled(job)) return RuntimeServerError.RuntimeJobCancelled;

        const escaped_content = try protocol.jsonEscape(self.allocator, provider_completion.assistant_text);
        defer self.allocator.free(escaped_content);
        const talk_args = try std.fmt.allocPrint(self.allocator, "{{\"message\":\"{s}\"}}", .{escaped_content});
        defer self.allocator.free(talk_args);
        self.runtime.queueToolUse(DEFAULT_BRAIN, "talk.user", talk_args) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        self.runPendingTicks(job, null) catch |err| {
            self.clearRuntimeOutboundLocked();
            if (err == RuntimeServerError.RuntimeJobCancelled) return err;
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        self.runtime.appendMessageMemory(DEFAULT_BRAIN, "assistant", provider_completion.assistant_text) catch |err| {
            self.clearRuntimeOutboundLocked();
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        const outbound = try self.runtime.drainOutbound(self.allocator);
        defer agent_runtime.deinitOutbound(self.allocator, outbound);

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        if (outbound.len == 0) {
            try responses.append(self.allocator, try protocol.buildSessionReceive(self.allocator, request_id, "ok"));
        } else {
            for (outbound) |message| {
                try responses.append(self.allocator, try protocol.buildSessionReceive(self.allocator, request_id, message));
            }
        }

        return responses.toOwnedSlice(self.allocator);
    }

    fn clearRuntimeOutboundLocked(self: *RuntimeServer) void {
        for (self.runtime.outbound_messages.items) |message| self.allocator.free(message);
        self.runtime.outbound_messages.clearRetainingCapacity();
    }

    fn handleControl(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        action: ?[]const u8,
        content: ?[]const u8,
    ) ![][]u8 {
        const control_action = action orelse "";

        if (std.mem.eql(u8, control_action, "goal") or std.mem.eql(u8, control_action, "plan")) {
            const goal = content orelse return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                self.allocator,
                request_id,
                .missing_content,
                "agent.control goal requires content",
            ));
            return self.handleChat(job, request_id, goal);
        }

        return self.wrapSingleFrame(try protocol.buildErrorWithCode(
            self.allocator,
            request_id,
            .unsupported_message_type,
            "unsupported agent.control action in chat-only mode",
        ));
    }

    fn runPendingTicks(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        tool_payloads: ?*std.ArrayListUnmanaged([]u8),
    ) !void {
        const started_ms = std.time.milliTimestamp();

        while (true) {
            if (self.isJobCancelled(job)) return RuntimeServerError.RuntimeJobCancelled;

            if (std.time.milliTimestamp() - started_ms > INTERNAL_TICK_TIMEOUT_MS) {
                return RuntimeServerError.RuntimeTickTimeout;
            }

            const tick_opt = try self.runtime.tickNext();
            if (tick_opt == null) break;

            var tick = tick_opt.?;
            defer tick.deinit(self.allocator);

            for (tick.tool_results) |result| {
                if (tool_payloads) |payloads| {
                    try payloads.append(self.allocator, try self.allocator.dupe(u8, result.payload_json));
                }
            }
        }
    }

    pub fn buildRuntimeErrorResponse(self: *RuntimeServer, request_id: []const u8, err: anyerror) ![]u8 {
        return switch (err) {
            agent_runtime.RuntimeError.QueueSaturated => protocol.buildErrorWithCode(self.allocator, request_id, .queue_saturated, "runtime queue saturated"),
            agent_runtime.RuntimeError.RuntimePaused => protocol.buildErrorWithCode(self.allocator, request_id, .runtime_paused, "runtime is paused"),
            agent_runtime.RuntimeError.RuntimeCancelled => protocol.buildErrorWithCode(self.allocator, request_id, .runtime_cancelled, "runtime is cancelled"),
            RuntimeServerError.RuntimeTickTimeout => protocol.buildErrorWithCode(self.allocator, request_id, .runtime_timeout, "runtime tick timeout"),
            RuntimeServerError.RuntimeJobTimeout => protocol.buildErrorWithCode(self.allocator, request_id, .runtime_timeout, "runtime operation timeout"),
            RuntimeServerError.ProviderModelNotFound => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "provider model not found"),
            RuntimeServerError.MissingProviderApiKey => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "missing provider API key"),
            RuntimeServerError.ProviderStreamFailed => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "provider stream failed"),
            RuntimeServerError.ProviderToolLoopExceeded => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "provider tool loop exceeded limits"),
            else => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, @errorName(err)),
        };
    }

    fn wrapRuntimeErrorResponse(self: *RuntimeServer, request_id: []const u8, err: anyerror) ![][]u8 {
        return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
    }

    fn wrapSingleFrame(self: *RuntimeServer, payload: []u8) ![][]u8 {
        const frames = try self.allocator.alloc([]u8, 1);
        frames[0] = payload;
        return frames;
    }

    fn completeWithProvider(self: *RuntimeServer, job: *RuntimeQueueJob, brain_name: []const u8) !ProviderCompletion {
        const provider_runtime = &(self.provider_runtime orelse return RuntimeServerError.ProviderModelNotFound);

        var provider_name: []const u8 = provider_runtime.default_provider_name;
        var model_name: ?[]const u8 = provider_runtime.default_model_name;
        var think_level: ?[]const u8 = null;

        var specialization = brain_specialization.loadBrainSpecialization(self.allocator, &self.runtime, brain_name) catch |err| blk: {
            std.log.warn("Failed loading provider specialization for {s}: {s}", .{ brain_name, @errorName(err) });
            break :blk null;
        };
        defer if (specialization) |*spec| spec.deinit();

        if (specialization) |spec| {
            if (spec.provider_name) |value| {
                const provider_changed = !std.mem.eql(u8, provider_name, value);
                provider_name = value;
                if (provider_changed and spec.model_name == null) {
                    model_name = null;
                }
            }
            if (spec.model_name) |value| model_name = value;
            if (spec.think_level) |value| think_level = value;
        }
        if (self.runtime.getBrainProviderOverride(brain_name)) |runtime_override| {
            if (runtime_override.provider_name) |value| {
                const provider_changed = !std.mem.eql(u8, provider_name, value);
                provider_name = value;
                if (provider_changed and runtime_override.model_name == null) {
                    model_name = null;
                }
            }
            if (runtime_override.model_name) |value| model_name = value;
            if (runtime_override.think_level) |value| think_level = value;
        }

        const model = selectModel(provider_runtime, provider_name, model_name) orelse return RuntimeServerError.ProviderModelNotFound;

        const api_key = try self.resolveApiKey(provider_runtime, model.provider);
        defer self.allocator.free(api_key);

        const world_tool_specs = try self.runtime.world_tools.exportProviderWorldTools(self.allocator);
        defer tool_registry.deinitProviderTools(self.allocator, world_tool_specs);

        const provider_tools = try self.allocator.alloc(ziggy_piai.types.Tool, world_tool_specs.len);
        defer self.allocator.free(provider_tools);
        for (world_tool_specs, 0..) |spec, idx| {
            provider_tools[idx] = .{
                .name = spec.name,
                .description = spec.description,
                .parameters_json = spec.parameters_json,
            };
        }

        var round: usize = 0;
        var total_calls: usize = 0;
        while (round < MAX_PROVIDER_TOOL_ROUNDS) : (round += 1) {
            const active_memory_prompt = try self.buildProviderActiveMemoryPrompt(brain_name);
            defer self.allocator.free(active_memory_prompt);

            var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(self.allocator);
            defer {
                deinitAssistantEvents(self.allocator, &events);
                events.deinit();
            }

            const messages = [_]ziggy_piai.types.Message{
                .{
                    .role = .user,
                    .content = active_memory_prompt,
                },
            };
            const context = ziggy_piai.types.Context{
                .messages = &messages,
                .tools = provider_tools,
            };

            streamByModelFn(
                self.allocator,
                &provider_runtime.http_client,
                &provider_runtime.api_registry,
                model,
                context,
                .{
                    .api_key = api_key,
                    .reasoning = think_level,
                },
                &events,
            ) catch return RuntimeServerError.ProviderStreamFailed;

            var assistant = try extractAssistantMessage(self.allocator, events.items);
            errdefer deinitOwnedAssistantMessage(self.allocator, &assistant);

            const tool_calls = assistant.tool_calls;
            if (tool_calls.len == 0) {
                const final_text = try self.allocator.dupe(u8, assistant.text);
                deinitOwnedAssistantMessage(self.allocator, &assistant);
                return .{
                    .assistant_text = final_text,
                };
            }

            if (total_calls + tool_calls.len > MAX_PROVIDER_TOOL_CALLS_PER_TURN) {
                return RuntimeServerError.ProviderToolLoopExceeded;
            }
            total_calls += tool_calls.len;

            try self.appendAssistantToolCallMessage(brain_name, assistant.text, tool_calls);

            for (tool_calls) |tool_call| {
                const args_with_call_id = try injectToolCallId(self.allocator, tool_call.arguments_json, tool_call.id);
                defer self.allocator.free(args_with_call_id);
                try self.runtime.queueToolUse(brain_name, tool_call.name, args_with_call_id);
            }

            var tool_payloads = std.ArrayListUnmanaged([]u8){};
            defer {
                for (tool_payloads.items) |payload| self.allocator.free(payload);
                tool_payloads.deinit(self.allocator);
            }

            self.runPendingTicks(job, &tool_payloads) catch |err| {
                if (err == RuntimeServerError.RuntimeJobCancelled) return err;
                return err;
            };
            deinitOwnedAssistantMessage(self.allocator, &assistant);
        }

        return RuntimeServerError.ProviderToolLoopExceeded;
    }

    fn resolveApiKey(self: *RuntimeServer, provider_runtime: *const ProviderRuntime, provider_name: []const u8) ![]const u8 {
        if (provider_runtime.credentials.getProviderApiKey(provider_name)) |key| {
            return key;
        }
        if (builtin.is_test) {
            if (provider_runtime.test_only_api_key) |key| return try self.allocator.dupe(u8, key);
        }
        if (getEnvApiKeyFn(self.allocator, provider_name)) |key| {
            return key;
        }
        return RuntimeServerError.MissingProviderApiKey;
    }

    fn selectModel(provider_runtime: *const ProviderRuntime, provider_name: []const u8, model_name: ?[]const u8) ?ziggy_piai.types.Model {
        if (model_name) |selected_model_name| {
            return provider_runtime.model_registry.getModel(provider_name, selected_model_name);
        }

        for (provider_runtime.model_registry.models.items) |model| {
            if (std.mem.eql(u8, model.provider, provider_name)) return model;
        }
        return null;
    }

    fn buildProviderActiveMemoryPrompt(self: *RuntimeServer, brain_name: []const u8) ![]u8 {
        const snapshot = try self.runtime.active_memory.snapshotActive(self.allocator, brain_name);
        defer memory.deinitItems(self.allocator, snapshot);

        const state_json = try memory.toActiveMemoryJson(self.allocator, brain_name, snapshot);
        defer self.allocator.free(state_json);

        return std.fmt.allocPrint(
            self.allocator,
            "<active_memory_state>\n{s}</active_memory_state>\nUse only this state as conversation context.",
            .{state_json},
        );
    }

    fn appendAssistantToolCallMessage(
        self: *RuntimeServer,
        brain_name: []const u8,
        content: []const u8,
        tool_calls: []const ziggy_piai.types.ToolCall,
    ) !void {
        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);

        try payload.appendSlice(self.allocator, "{\"role\":\"assistant\",\"content\":\"");
        const escaped_content = try protocol.jsonEscape(self.allocator, content);
        defer self.allocator.free(escaped_content);
        try payload.appendSlice(self.allocator, escaped_content);
        try payload.appendSlice(self.allocator, "\",\"tool_calls\":[");

        for (tool_calls, 0..) |tool_call, idx| {
            if (idx > 0) try payload.append(self.allocator, ',');

            const escaped_id = try protocol.jsonEscape(self.allocator, tool_call.id);
            defer self.allocator.free(escaped_id);
            const escaped_name = try protocol.jsonEscape(self.allocator, tool_call.name);
            defer self.allocator.free(escaped_name);
            const escaped_args = try protocol.jsonEscape(self.allocator, tool_call.arguments_json);
            defer self.allocator.free(escaped_args);

            try payload.appendSlice(self.allocator, "{\"id\":\"");
            try payload.appendSlice(self.allocator, escaped_id);
            try payload.appendSlice(self.allocator, "\",\"name\":\"");
            try payload.appendSlice(self.allocator, escaped_name);
            try payload.appendSlice(self.allocator, "\",\"arguments_json\":\"");
            try payload.appendSlice(self.allocator, escaped_args);
            try payload.appendSlice(self.allocator, "\"}");
        }

        try payload.appendSlice(self.allocator, "]}");
        const content_json = try payload.toOwnedSlice(self.allocator);
        defer self.allocator.free(content_json);

        var created = try self.runtime.active_memory.create(brain_name, .ram, null, "message", content_json);
        created.deinit(self.allocator);
    }

    fn operationTimeoutNs(self: *const RuntimeServer, operation_class: RuntimeOperationClass) u64 {
        const timeout_ms = switch (operation_class) {
            .chat => self.chat_operation_timeout_ms,
            .control => self.control_operation_timeout_ms,
        };
        return timeout_ms * std.time.ns_per_ms;
    }
};

fn isChatLikeControlAction(action: ?[]const u8) bool {
    const control_action = action orelse "state";
    return std.mem.eql(u8, control_action, "goal") or std.mem.eql(u8, control_action, "plan");
}

fn injectToolCallId(allocator: std.mem.Allocator, args_json: []const u8, call_id: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, args_json, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '{' or trimmed[trimmed.len - 1] != '}') {
        return error.InvalidToolArgs;
    }

    const escaped_call_id = try protocol.jsonEscape(allocator, call_id);
    defer allocator.free(escaped_call_id);

    const inner = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t\r\n");
    if (inner.len == 0) {
        return std.fmt.allocPrint(allocator, "{{\"_tool_call_id\":\"{s}\"}}", .{escaped_call_id});
    }
    return std.fmt.allocPrint(
        allocator,
        "{{\"_tool_call_id\":\"{s}\",{s}}}",
        .{ escaped_call_id, inner },
    );
}

fn extractAssistantMessage(
    allocator: std.mem.Allocator,
    events: []const ziggy_piai.types.AssistantMessageEvent,
) !ziggy_piai.types.AssistantMessage {
    var text_acc = std.ArrayListUnmanaged(u8){};
    defer text_acc.deinit(allocator);

    for (events) |event| {
        switch (event) {
            .text_delta => |delta| try text_acc.appendSlice(allocator, delta.delta),
            .done => |done| {
                const copied_tool_calls = try cloneToolCalls(allocator, done.tool_calls);
                const owned_text = if (done.text.len > 0)
                    try allocator.dupe(u8, done.text)
                else
                    try text_acc.toOwnedSlice(allocator);
                return .{
                    .text = owned_text,
                    .thinking = try allocator.dupe(u8, ""),
                    .tool_calls = copied_tool_calls,
                    .api = "",
                    .provider = "",
                    .model = "",
                    .usage = done.usage,
                    .stop_reason = done.stop_reason,
                    .error_message = null,
                };
            },
            .err => return RuntimeServerError.ProviderStreamFailed,
            else => {},
        }
    }

    return .{
        .text = try text_acc.toOwnedSlice(allocator),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = &.{},
        .api = "",
        .provider = "",
        .model = "",
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    };
}

fn cloneToolCalls(allocator: std.mem.Allocator, source: []const ziggy_piai.types.ToolCall) ![]const ziggy_piai.types.ToolCall {
    if (source.len == 0) return &.{};
    const cloned = try allocator.alloc(ziggy_piai.types.ToolCall, source.len);
    errdefer allocator.free(cloned);

    for (source, 0..) |tool_call, idx| {
        cloned[idx] = .{
            .id = try allocator.dupe(u8, tool_call.id),
            .name = try allocator.dupe(u8, tool_call.name),
            .arguments_json = try allocator.dupe(u8, tool_call.arguments_json),
        };
    }
    return cloned;
}

fn deinitOwnedAssistantMessage(allocator: std.mem.Allocator, msg: *ziggy_piai.types.AssistantMessage) void {
    if (msg.text.len > 0) allocator.free(msg.text);
    if (msg.thinking.len > 0) allocator.free(msg.thinking);
    if (msg.error_message) |value| allocator.free(value);
    if (msg.tool_calls.len > 0) {
        for (msg.tool_calls) |tool_call| {
            allocator.free(tool_call.id);
            allocator.free(tool_call.name);
            allocator.free(tool_call.arguments_json);
        }
        allocator.free(msg.tool_calls);
    }
    msg.* = undefined;
}

fn deinitAssistantMessage(allocator: std.mem.Allocator, msg: *ziggy_piai.types.AssistantMessage) void {
    if (msg.text.len > 0) allocator.free(msg.text);
    if (msg.thinking.len > 0) allocator.free(msg.thinking);
    if (msg.error_message) |value| allocator.free(value);
    for (msg.tool_calls) |tool_call| {
        allocator.free(tool_call.id);
        allocator.free(tool_call.name);
        allocator.free(tool_call.arguments_json);
    }
    if (msg.tool_calls.len > 0) allocator.free(msg.tool_calls);
}

fn deinitAssistantEvents(
    allocator: std.mem.Allocator,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) void {
    for (events.items) |*event| {
        switch (event.*) {
            .start => |*msg| deinitAssistantMessage(allocator, msg),
            .done => |*msg| deinitAssistantMessage(allocator, msg),
            .text_delta => |*delta| allocator.free(delta.delta),
            .text_end => |*end| allocator.free(end.content),
            .thinking_delta => |*delta| allocator.free(delta.delta),
            .thinking_end => |*end| allocator.free(end.content),
            .toolcall_delta => |*delta| allocator.free(delta.delta),
            .toolcall_end => |*end| {
                allocator.free(end.tool_call.id);
                allocator.free(end.tool_call.name);
                allocator.free(end.tool_call.arguments_json);
            },
            .err => |value| allocator.free(value),
            else => {},
        }
    }
}

const AsyncRequestCtx = struct {
    allocator: std.mem.Allocator,
    server: *RuntimeServer,
    request_json: []const u8,
    response: ?[]u8 = null,
    err_name: ?[]u8 = null,

    fn deinit(self: *AsyncRequestCtx) void {
        if (self.response) |payload| self.allocator.free(payload);
        if (self.err_name) |err| self.allocator.free(err);
    }
};

fn runRequestInThread(ctx: *AsyncRequestCtx) void {
    ctx.response = ctx.server.handleMessage(ctx.request_json) catch |err| {
        ctx.err_name = std.fmt.allocPrint(ctx.allocator, "{s}", .{@errorName(err)}) catch null;
        return;
    };
}

fn mockProviderStreamByModel(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    try std.testing.expect(std.mem.eql(u8, model.provider, "openai"));
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "mock provider response"),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    } });
}

var mockToolLoopCallCount: usize = 0;
var mockCapturedProviderName: ?[]const u8 = null;
var mockCapturedModelName: ?[]const u8 = null;
var mockCapturedReasoning: ?[]const u8 = null;
var mockCapturedApiKey: ?[]u8 = null;

fn mockProviderStreamCaptureConfig(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    options: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    mockCapturedProviderName = model.provider;
    mockCapturedModelName = model.id;
    mockCapturedReasoning = options.reasoning;
    if (mockCapturedApiKey) |existing| {
        allocator.free(existing);
        mockCapturedApiKey = null;
    }
    if (options.api_key) |value| {
        mockCapturedApiKey = try allocator.dupe(u8, value);
    }
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "captured provider response"),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    } });
}

fn mockGetEnvApiKeyForOpenAi(allocator: std.mem.Allocator, provider: []const u8) ?[]const u8 {
    if (!std.mem.eql(u8, provider, "openai")) return null;
    return allocator.dupe(u8, "env-openai-key") catch null;
}

fn writeAgentJsonForTest(allocator: std.mem.Allocator, agent_id: []const u8, brain_name: []const u8, content: []const u8) !void {
    const agents_root = try std.fs.path.join(allocator, &.{ "agents", agent_id });
    defer allocator.free(agents_root);

    const dir = if (std.mem.eql(u8, brain_name, "primary"))
        try allocator.dupe(u8, agents_root)
    else
        try std.fs.path.join(allocator, &.{ agents_root, brain_name });
    defer allocator.free(dir);

    try std.fs.cwd().makePath(dir);
    const file_path = try std.fs.path.join(allocator, &.{ dir, "agent.json" });
    defer allocator.free(file_path);
    try std.fs.cwd().writeFile(.{
        .sub_path = file_path,
        .data = content,
    });
}

fn mockProviderStreamByModelWithToolLoop(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    try std.testing.expect(context.tools != null);
    if (mockToolLoopCallCount == 0) {
        mockToolLoopCallCount += 1;
        const tool_calls = try allocator.alloc(ziggy_piai.types.ToolCall, 1);
        tool_calls[0] = .{
            .id = try allocator.dupe(u8, "call-1"),
            .name = try allocator.dupe(u8, "file.list"),
            .arguments_json = try allocator.dupe(u8, "{\"path\":\"src\"}"),
        };
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, ""),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = tool_calls,
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .tool_use,
            .error_message = null,
        } });
        return;
    }

    try std.testing.expectEqual(@as(usize, 1), context.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"active_memory\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"tool_result\"") != null);
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "tool loop complete"),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = &.{},
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    } });
}

fn mockProviderStreamByModelTooManyToolCalls(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    const tool_count = MAX_PROVIDER_TOOL_CALLS_PER_TURN + 1;
    const tool_calls = try allocator.alloc(ziggy_piai.types.ToolCall, tool_count);
    for (tool_calls, 0..) |*tool_call, idx| {
        tool_call.* = .{
            .id = try std.fmt.allocPrint(allocator, "call-{d}", .{idx}),
            .name = try allocator.dupe(u8, "file.list"),
            .arguments_json = try allocator.dupe(u8, "{\"path\":\"src\"}"),
        };
    }

    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, ""),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = tool_calls,
        .api = model.api,
        .provider = model.provider,
        .model = model.id,
        .usage = .{},
        .stop_reason = .tool_use,
        .error_message = null,
    } });
}

fn mockProviderStreamByModelError(
    _: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    _: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    return error.MockProviderUnavailable;
}

fn mockProviderStreamByModelSlow(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    std.Thread.sleep(50 * std.time.ns_per_ms);
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "slow provider response"),
        .thinking = try allocator.dupe(u8, ""),
        .tool_calls = &.{},
        .api = "chat",
        .provider = "openai",
        .model = "gpt-4o-mini",
        .usage = .{},
        .stop_reason = .stop,
        .error_message = null,
    } });
}

test "runtime_server: session.send dispatches through runtime and emits session.receive" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-1\",\"type\":\"session.send\",\"content\":\"hello runtime\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "hello runtime") != null);
}

test "runtime_server: empty ltm config in tests provisions sqlite-backed runtime" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    try std.testing.expect(server.runtime.ltm_store != null);
    try std.testing.expect(server.test_ltm_directory != null);
}

test "runtime_server: session.send returns all outbound runtime frames" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-frames\",\"type\":\"session.send\",\"content\":\"hello runtime\"}");
    defer deinitResponseFrames(allocator, responses);

    try std.testing.expectEqual(@as(usize, 1), responses.len);

    var session_receive_count: usize = 0;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"session.receive\"") != null) session_receive_count += 1;
        try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"tool.event\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"memory.event\"") == null);
    }

    try std.testing.expectEqual(@as(usize, 1), session_receive_count);
}

test "runtime_server: provider-backed session.send uses configured provider runtime" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModel;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer deinitResponseFrames(allocator, responses);

    var found_provider_text = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "mock provider response") != null) {
            found_provider_text = true;
            break;
        }
    }

    try std.testing.expect(found_provider_text);

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, snapshot_json, .{});
    defer parsed.deinit();

    const items = parsed.value.object.get("active_memory").?.object.get("items").?.array.items;
    var assistant_turns: usize = 0;
    for (items) |item| {
        if (item.object.get("kind").?.string.len == 0) continue;
        if (!std.mem.eql(u8, item.object.get("kind").?.string, "message")) continue;
        const content_obj = item.object.get("content").?.object;
        const role = content_obj.get("role").?.string;
        const text = content_obj.get("content").?.string;
        if (std.mem.eql(u8, role, "assistant") and std.mem.eql(u8, text, "mock provider response")) {
            assistant_turns += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), assistant_turns);
}

test "runtime_server: provider-only override resets inherited model selection" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamCaptureConfig;
    mockCapturedProviderName = null;
    mockCapturedModelName = null;
    mockCapturedReasoning = null;
    if (mockCapturedApiKey) |value| {
        allocator.free(value);
        mockCapturedApiKey = null;
    }
    defer if (mockCapturedApiKey) |value| {
        allocator.free(value);
        mockCapturedApiKey = null;
    };

    const server = try RuntimeServer.createWithProvider(allocator, "agent-provider-only-override", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "configured-openai-key",
    });
    defer server.destroy();

    try server.runtime.setBrainProviderOverride("primary", .{
        .provider_name = "openai-codex",
    });

    const response = try server.handleMessage("{\"id\":\"req-provider-only-override\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "captured provider response") != null);
    try std.testing.expectEqualStrings("openai-codex", mockCapturedProviderName.?);
    try std.testing.expectEqualStrings("gpt-5.1-codex-mini", mockCapturedModelName.?);
    try std.testing.expect(mockCapturedApiKey != null);
    try std.testing.expectEqualStrings("configured-openai-key", mockCapturedApiKey.?);
}

test "runtime_server: provider runtime falls back to env API key on secure-store miss" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamCaptureConfig;

    const original_env_key_fn = getEnvApiKeyFn;
    defer getEnvApiKeyFn = original_env_key_fn;
    getEnvApiKeyFn = mockGetEnvApiKeyForOpenAi;

    mockCapturedProviderName = null;
    mockCapturedModelName = null;
    mockCapturedReasoning = null;
    if (mockCapturedApiKey) |value| {
        allocator.free(value);
        mockCapturedApiKey = null;
    }
    defer if (mockCapturedApiKey) |value| {
        allocator.free(value);
        mockCapturedApiKey = null;
    };

    const server = try RuntimeServer.createWithProvider(allocator, "agent-env-fallback", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
    });
    defer server.destroy();

    // Make lookup deterministic for the test regardless of host keyring contents.
    server.provider_runtime.?.credentials.backend = .none;

    const response = try server.handleMessage("{\"id\":\"req-provider-env-fallback\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "captured provider response") != null);
    try std.testing.expectEqualStrings("openai", mockCapturedProviderName.?);
    try std.testing.expect(mockCapturedApiKey != null);
    try std.testing.expectEqualStrings("env-openai-key", mockCapturedApiKey.?);
}

test "runtime_server: agent.json can override primary brain provider model and think level" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamCaptureConfig;
    mockCapturedProviderName = null;
    mockCapturedModelName = null;
    mockCapturedReasoning = null;

    const agent_id = "agent-provider-json-override";
    const agent_dir = try std.fs.path.join(allocator, &.{ "agents", agent_id });
    defer allocator.free(agent_dir);
    std.fs.cwd().deleteTree(agent_dir) catch {};
    defer std.fs.cwd().deleteTree(agent_dir) catch {};

    try writeAgentJsonForTest(allocator, agent_id, "primary",
        \\{
        \\  "provider": "openai-codex",
        \\  "model": "gpt-5.1-codex-mini",
        \\  "think_level": "high"
        \\}
    );

    const server = try RuntimeServer.createWithProvider(allocator, agent_id, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-json-override\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "captured provider response") != null);
    try std.testing.expectEqualStrings("openai-codex", mockCapturedProviderName.?);
    try std.testing.expectEqualStrings("gpt-5.1-codex-mini", mockCapturedModelName.?);
    try std.testing.expectEqualStrings("high", mockCapturedReasoning.?);
}

test "runtime_server: runtime override supersedes and can clear file provider specialization" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamCaptureConfig;

    const agent_id = "agent-provider-runtime-override";
    const agent_dir = try std.fs.path.join(allocator, &.{ "agents", agent_id });
    defer allocator.free(agent_dir);
    std.fs.cwd().deleteTree(agent_dir) catch {};
    defer std.fs.cwd().deleteTree(agent_dir) catch {};

    try writeAgentJsonForTest(allocator, agent_id, "primary",
        \\{
        \\  "provider": "openai-codex",
        \\  "model": "gpt-5.1-codex-mini",
        \\  "think_level": "low"
        \\}
    );

    const server = try RuntimeServer.createWithProvider(allocator, agent_id, .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    try server.runtime.setBrainProviderOverride("primary", .{
        .provider_name = "openai-codex",
        .model_name = "gpt-5.2",
        .think_level = "high",
    });

    mockCapturedProviderName = null;
    mockCapturedModelName = null;
    mockCapturedReasoning = null;
    const overridden = try server.handleMessage("{\"id\":\"req-provider-runtime-override-1\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(overridden);
    try std.testing.expect(std.mem.indexOf(u8, overridden, "captured provider response") != null);
    try std.testing.expectEqualStrings("openai-codex", mockCapturedProviderName.?);
    try std.testing.expectEqualStrings("gpt-5.2", mockCapturedModelName.?);
    try std.testing.expectEqualStrings("high", mockCapturedReasoning.?);

    try server.runtime.setBrainProviderOverride("primary", .{});

    mockCapturedProviderName = null;
    mockCapturedModelName = null;
    mockCapturedReasoning = null;
    const reverted = try server.handleMessage("{\"id\":\"req-provider-runtime-override-2\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(reverted);
    try std.testing.expect(std.mem.indexOf(u8, reverted, "captured provider response") != null);
    try std.testing.expectEqualStrings("openai-codex", mockCapturedProviderName.?);
    try std.testing.expectEqualStrings("gpt-5.1-codex-mini", mockCapturedModelName.?);
    try std.testing.expectEqualStrings("low", mockCapturedReasoning.?);
}

test "runtime_server: provider tool loop executes world tool and returns final response" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithToolLoop;
    mockToolLoopCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-tools\",\"type\":\"session.send\",\"content\":\"use tools\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "tool loop complete") != null) saw_final = true;
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(saw_final);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"kind\":\"tool_result\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"tool_calls\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"id\":\"call-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"name\":\"file.list\"") != null);
}

test "runtime_server: provider tool-call cap does not persist unexecuted tool-call metadata" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelTooManyToolCalls;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-too-many-tools\",\"type\":\"session.send\",\"content\":\"use many tools\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"execution_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "provider tool loop exceeded limits") != null);

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "use many tools") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"tool_calls\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"assistant\"") == null);
}

test "runtime_server: provider failure does not leak queued user/tick events" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelError;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .inbound_queue_max = 1,
        .brain_tick_queue_max = 1,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        const response = try server.handleMessage("{\"id\":\"req-provider-fail\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
        defer allocator.free(response);

        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"execution_failed\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"queue_saturated\"") == null);
        try std.testing.expectEqual(@as(usize, 0), server.runtime.tick_queue.items.len);
        try std.testing.expectEqual(@as(usize, 0), server.runtime.bus.pendingCount());
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "hello provider") != null);
}

test "runtime_server: timed out provider session.send does not enqueue runtime work after cancellation" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelSlow;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .chat_operation_timeout_ms = 10,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-timeout\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"runtime_timeout\"") != null);

    std.Thread.sleep(80 * std.time.ns_per_ms);

    server.runtime_mutex.lock();
    defer server.runtime_mutex.unlock();
    try std.testing.expectEqual(@as(u64, 0), server.runtime.checkpoint);
    try std.testing.expectEqual(@as(usize, 0), server.runtime.bus.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), server.runtime.tick_queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.runtime.outbound_messages.items.len);
    const primary = server.runtime.brains.getPtr("primary").?;
    try std.testing.expectEqual(@as(usize, 0), primary.pending_tool_uses.items.len);

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "hello provider") != null);
}

test "runtime_server: talk enqueue failure does not leave pending runtime work" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .brain_tick_queue_max = 0,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        const response = try server.handleMessage("{\"id\":\"req-talk-sat\",\"type\":\"session.send\",\"content\":\"hello\"}");
        defer allocator.free(response);

        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"queue_saturated\"") != null);
        try std.testing.expectEqual(@as(usize, 0), server.runtime.tick_queue.items.len);
        try std.testing.expectEqual(@as(usize, 0), server.runtime.bus.pendingCount());
        const primary = server.runtime.brains.getPtr("primary").?;
        try std.testing.expectEqual(@as(usize, 0), primary.pending_tool_uses.items.len);
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"role\":\"assistant\"") == null);
}

test "runtime_server: runPendingTicks failure clears stale outbound queue" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .outbound_queue_max = 0,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        const response = try server.handleMessage("{\"id\":\"req-tick-fail\",\"type\":\"session.send\",\"content\":\"hello\"}");
        defer allocator.free(response);

        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"queue_saturated\"") != null);
        try std.testing.expectEqual(@as(usize, 0), server.runtime.outbound_messages.items.len);
    }
}

test "runtime_server: non-chat agent.control actions are unsupported" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    const actions = [_][]const u8{ "state", "status", "pause", "resume", "cancel" };
    for (actions) |action| {
        const request = try std.fmt.allocPrint(
            allocator,
            "{{\"id\":\"req-ctrl-{s}\",\"type\":\"agent.control\",\"action\":\"{s}\"}}",
            .{ action, action },
        );
        defer allocator.free(request);
        const response = try server.handleMessage(request);
        defer allocator.free(response);
        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"unsupported_message_type\"") != null);
    }
}

test "runtime_server: queue saturation returns coded queue_saturated error" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .inbound_queue_max = 512,
        .brain_tick_queue_max = 1,
        .outbound_queue_max = 1,
        .control_queue_max = 1,
        .runtime_request_queue_max = 0,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    const blocked = try server.handleMessage("{\"id\":\"req-20\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer allocator.free(blocked);

    try std.testing.expect(std.mem.indexOf(u8, blocked, "\"code\":\"queue_saturated\"") != null);
}

test "runtime_server: operation timeout policy prefers longer chat timeout" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();
    try std.testing.expect(server.operationTimeoutNs(.chat) > server.operationTimeoutNs(.control));
}

test "runtime_server: queued control request times out with runtime_timeout code" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .control_operation_timeout_ms = 10,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    server.runtime_mutex.lock();
    var runtime_locked = true;
    defer if (runtime_locked) server.runtime_mutex.unlock();

    var ctx = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-timeout\",\"type\":\"agent.control\",\"action\":\"state\"}",
    };
    defer ctx.deinit();

    const thread = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx});
    std.Thread.sleep(50 * std.time.ns_per_ms);
    server.runtime_mutex.unlock();
    runtime_locked = false;
    thread.join();

    try std.testing.expect(ctx.err_name == null);
    try std.testing.expect(ctx.response != null);
    try std.testing.expect(std.mem.indexOf(u8, ctx.response.?, "\"code\":\"runtime_timeout\"") != null);
}

test "runtime_server: agent.control goal/plan use chat timeout class" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .chat_operation_timeout_ms = 120,
        .control_operation_timeout_ms = 10,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    const requests = [_][]const u8{
        "{\"id\":\"req-goal-timeout-class\",\"type\":\"agent.control\",\"action\":\"goal\",\"content\":\"hello\"}",
        "{\"id\":\"req-plan-timeout-class\",\"type\":\"agent.control\",\"action\":\"plan\",\"content\":\"hello\"}",
    };

    for (requests) |request_json| {
        server.runtime_mutex.lock();
        var runtime_locked = true;
        defer if (runtime_locked) server.runtime_mutex.unlock();

        var ctx = AsyncRequestCtx{
            .allocator = allocator,
            .server = server,
            .request_json = request_json,
        };
        defer ctx.deinit();

        const thread = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx});
        std.Thread.sleep(40 * std.time.ns_per_ms);
        server.runtime_mutex.unlock();
        runtime_locked = false;
        thread.join();

        try std.testing.expect(ctx.err_name == null);
        try std.testing.expect(ctx.response != null);
        try std.testing.expect(std.mem.indexOf(u8, ctx.response.?, "\"code\":\"runtime_timeout\"") == null);
        try std.testing.expect(std.mem.indexOf(u8, ctx.response.?, "\"type\":\"session.receive\"") != null);
    }
}

test "runtime_server: timed out queued control action does not execute later" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .control_operation_timeout_ms = 10,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    server.runtime_mutex.lock();
    var runtime_locked = true;
    defer if (runtime_locked) server.runtime_mutex.unlock();

    var ctx = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-timeout-cancel\",\"type\":\"agent.control\",\"action\":\"cancel\"}",
    };
    defer ctx.deinit();

    const thread = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx});
    std.Thread.sleep(50 * std.time.ns_per_ms);
    server.runtime_mutex.unlock();
    runtime_locked = false;
    thread.join();

    try std.testing.expect(ctx.err_name == null);
    try std.testing.expect(ctx.response != null);
    try std.testing.expect(std.mem.indexOf(u8, ctx.response.?, "\"code\":\"runtime_timeout\"") != null);

    server.runtime_mutex.lock();
    defer server.runtime_mutex.unlock();
    try std.testing.expectEqual(agent_runtime.RuntimeState.running, server.runtime.state);
    try std.testing.expectEqual(@as(usize, 0), server.runtime.control_events.items.len);
}

test "runtime_server: concurrent queue pressure yields deterministic queue_saturated" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .runtime_worker_threads = 1,
        .runtime_request_queue_max = 1,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    server.runtime_mutex.lock();
    var runtime_locked = true;
    defer if (runtime_locked) server.runtime_mutex.unlock();

    var ctx1 = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-q1\",\"type\":\"session.send\",\"content\":\"one\"}",
    };
    defer ctx1.deinit();
    var ctx2 = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-q2\",\"type\":\"session.send\",\"content\":\"two\"}",
    };
    defer ctx2.deinit();
    var ctx3 = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-q3\",\"type\":\"session.send\",\"content\":\"three\"}",
    };
    defer ctx3.deinit();

    const t1 = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx1});
    std.Thread.sleep(1 * std.time.ns_per_ms);
    const t2 = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx2});
    std.Thread.sleep(1 * std.time.ns_per_ms);
    const t3 = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx3});

    std.Thread.sleep(10 * std.time.ns_per_ms);
    server.runtime_mutex.unlock();
    runtime_locked = false;

    t1.join();
    t2.join();
    t3.join();

    try std.testing.expect(ctx1.err_name == null);
    try std.testing.expect(ctx2.err_name == null);
    try std.testing.expect(ctx3.err_name == null);
    try std.testing.expect(ctx1.response != null);
    try std.testing.expect(ctx2.response != null);
    try std.testing.expect(ctx3.response != null);

    const responses = [_][]const u8{ ctx1.response.?, ctx2.response.?, ctx3.response.? };
    var saturated_count: usize = 0;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"code\":\"queue_saturated\"") != null) saturated_count += 1;
    }
    try std.testing.expect(saturated_count >= 1);
}

test "runtime_server: timed-out queued jobs are removed from queue accounting" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .runtime_worker_threads = 1,
        .runtime_request_queue_max = 1,
        .control_operation_timeout_ms = 15,
        .ltm_directory = "",
        .ltm_filename = "",
    });
    defer server.destroy();

    server.runtime_mutex.lock();
    var runtime_locked = true;
    defer if (runtime_locked) server.runtime_mutex.unlock();

    var ctx1 = AsyncRequestCtx{
        .allocator = allocator,
        .server = server,
        .request_json = "{\"id\":\"req-hol-1\",\"type\":\"agent.control\",\"action\":\"state\"}",
    };
    defer ctx1.deinit();

    const t1 = try std.Thread.spawn(.{}, runRequestInThread, .{&ctx1});
    defer t1.join();

    var saw_nonzero_queue = false;
    var spins: usize = 0;
    while (spins < 200) : (spins += 1) {
        server.queue_mutex.lock();
        const queued = server.runtime_jobs.items.len;
        server.queue_mutex.unlock();
        if (queued > 0) saw_nonzero_queue = true;
        if (saw_nonzero_queue and queued == 0) break;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    const second = try server.handleMessage("{\"id\":\"req-hol-2\",\"type\":\"agent.control\",\"action\":\"state\"}");
    defer allocator.free(second);
    try std.testing.expect(std.mem.indexOf(u8, second, "\"code\":\"runtime_timeout\"") != null);

    const third = try server.handleMessage("{\"id\":\"req-hol-3\",\"type\":\"agent.control\",\"action\":\"state\"}");
    defer allocator.free(third);
    try std.testing.expect(std.mem.indexOf(u8, third, "\"code\":\"runtime_timeout\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, third, "\"code\":\"queue_saturated\"") == null);

    server.runtime_mutex.unlock();
    runtime_locked = false;
    std.Thread.sleep(40 * std.time.ns_per_ms);

    try std.testing.expect(ctx1.err_name == null);
    try std.testing.expect(ctx1.response != null);
    try std.testing.expect(std.mem.indexOf(u8, ctx1.response.?, "\"code\":\"runtime_timeout\"") != null);
}
