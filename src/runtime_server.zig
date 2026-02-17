const std = @import("std");
const Config = @import("config.zig");
const protocol = @import("protocol.zig");
const agent_runtime = @import("agent_runtime.zig");
const ziggy_piai = @import("ziggy-piai");

pub const default_agent_id = "default";
const DEFAULT_BRAIN = "primary";
const INTERNAL_TICK_TIMEOUT_MS: i64 = 5 * 1000;

const RuntimeServerError = error{
    RuntimeTickTimeout,
    RuntimeJobTimeout,
    MissingJobResponse,
    ProviderModelNotFound,
    MissingProviderApiKey,
    ProviderStreamFailed,
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

const ProviderRuntime = struct {
    model_registry: ziggy_piai.models.ModelRegistry,
    api_registry: ziggy_piai.api_registry.ApiRegistry,
    http_client: std.http.Client,
    provider_name: []u8,
    model_name: ?[]u8,
    api_key: ?[]u8,
    base_url: ?[]u8,

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
            .provider_name = try allocator.dupe(u8, provider_cfg.name),
            .model_name = null,
            .api_key = null,
            .base_url = null,
        };
        errdefer provider.deinit(allocator);

        if (provider_cfg.model) |value| provider.model_name = try allocator.dupe(u8, value);
        if (provider_cfg.api_key) |value| provider.api_key = try allocator.dupe(u8, value);
        if (provider_cfg.base_url) |value| provider.base_url = try allocator.dupe(u8, value);

        return provider;
    }

    fn deinit(self: *ProviderRuntime, allocator: std.mem.Allocator) void {
        self.model_registry.deinit();
        self.api_registry.deinit();
        self.http_client.deinit();
        allocator.free(self.provider_name);
        if (self.model_name) |value| allocator.free(value);
        if (self.api_key) |value| allocator.free(value);
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
                if (runtime_cfg.ltm_directory.len == 0) null else runtime_cfg.ltm_directory,
                if (runtime_cfg.ltm_filename.len == 0) null else runtime_cfg.ltm_filename,
            ),
            .runtime_queue_max = runtime_cfg.runtime_request_queue_max,
            .chat_operation_timeout_ms = runtime_cfg.chat_operation_timeout_ms,
            .control_operation_timeout_ms = runtime_cfg.control_operation_timeout_ms,
            .runtime_workers = try allocator.alloc(std.Thread, worker_count),
            .provider_runtime = provider_runtime,
        };
        errdefer {
            self.runtime.deinit();
            allocator.free(self.runtime_workers);
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
                return self.submitRuntimeJobAndAwait(parsed.msg_type, request_id, parsed.content, parsed.action, .control);
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
        defer job.result_mutex.unlock();

        while (!job.done) {
            const now_ns = std.time.nanoTimestamp();
            if (now_ns >= deadline_ns) {
                job.cancelled = true;
                return RuntimeServerError.RuntimeJobTimeout;
            }

            const remaining_ns: u64 = @intCast(deadline_ns - now_ns);
            job.result_cond.timedWait(&job.result_mutex, remaining_ns) catch |err| switch (err) {
                error.Timeout => continue,
            };
        }

        const response = job.response orelse return RuntimeServerError.MissingJobResponse;
        job.response = null;
        self.destroyJob(job);
        return response;
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

            const response = self.processRuntimeJob(job) catch |err| blk: {
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
                return self.handleChat(job.request_id, content);
            },
            .agent_control => {
                return self.handleControl(job.request_id, job.action, job.content);
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

    fn handleChat(self: *RuntimeServer, request_id: []const u8, content: []const u8) ![][]u8 {
        const assistant_text = if (self.provider_runtime != null)
            self.completeWithProvider(content) catch |err| return self.wrapRuntimeErrorResponse(request_id, err)
        else
            try self.allocator.dupe(u8, content);
        defer self.allocator.free(assistant_text);

        self.runtime.enqueueUserEvent(content) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        const escaped_content = try protocol.jsonEscape(self.allocator, assistant_text);
        defer self.allocator.free(escaped_content);
        const talk_args = try std.fmt.allocPrint(self.allocator, "{{\"message\":\"{s}\"}}", .{escaped_content});
        defer self.allocator.free(talk_args);
        self.runtime.queueToolUse(DEFAULT_BRAIN, "talk.user", talk_args) catch |err| {
            self.runtime.rollbackQueuedUserPrimaryWork(content);
            return self.wrapRuntimeErrorResponse(request_id, err);
        };

        const runtime_events = self.runPendingTicks() catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err);
        };
        defer deinitResponseFrames(self.allocator, runtime_events);

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

        for (runtime_events) |event_payload| {
            try responses.append(self.allocator, try self.allocator.dupe(u8, event_payload));
        }

        return responses.toOwnedSlice(self.allocator);
    }

    fn handleControl(
        self: *RuntimeServer,
        request_id: []const u8,
        action: ?[]const u8,
        content: ?[]const u8,
    ) ![][]u8 {
        const control_action = action orelse "state";

        if (std.mem.eql(u8, control_action, "state") or std.mem.eql(u8, control_action, "status")) {
            return self.wrapSingleFrame(try protocol.buildAgentState(self.allocator, request_id, @tagName(self.runtime.state), self.runtime.checkpoint));
        }

        if (std.mem.eql(u8, control_action, "pause")) {
            self.runtime.setState(.paused) catch |err| return self.wrapRuntimeErrorResponse(request_id, err);
            return self.wrapSingleFrame(try protocol.buildAgentState(self.allocator, request_id, "paused", self.runtime.checkpoint));
        }

        if (std.mem.eql(u8, control_action, "resume")) {
            self.runtime.setState(.running) catch |err| return self.wrapRuntimeErrorResponse(request_id, err);
            return self.wrapSingleFrame(try protocol.buildAgentState(self.allocator, request_id, "running", self.runtime.checkpoint));
        }

        if (std.mem.eql(u8, control_action, "cancel")) {
            self.runtime.setState(.cancelled) catch |err| return self.wrapRuntimeErrorResponse(request_id, err);
            return self.wrapSingleFrame(try protocol.buildAgentState(self.allocator, request_id, "cancelled", self.runtime.checkpoint));
        }

        if (std.mem.eql(u8, control_action, "goal") or std.mem.eql(u8, control_action, "plan")) {
            const goal = content orelse return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                self.allocator,
                request_id,
                .missing_content,
                "agent.control goal requires content",
            ));
            return self.handleChat(request_id, goal);
        }

        return self.wrapSingleFrame(try protocol.buildErrorWithCode(
            self.allocator,
            request_id,
            .unsupported_message_type,
            "unsupported agent.control action",
        ));
    }

    fn runPendingTicks(self: *RuntimeServer) ![][]u8 {
        const started_ms = std.time.milliTimestamp();
        var runtime_events = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (runtime_events.items) |payload| self.allocator.free(payload);
            runtime_events.deinit(self.allocator);
        }

        while (true) {
            if (std.time.milliTimestamp() - started_ms > INTERNAL_TICK_TIMEOUT_MS) {
                return RuntimeServerError.RuntimeTickTimeout;
            }

            const tick_opt = try self.runtime.tickNext();
            if (tick_opt == null) break;

            var tick = tick_opt.?;
            defer tick.deinit(self.allocator);

            for (tick.tool_results) |result| {
                const event = try protocol.buildToolEvent(self.allocator, "runtime", result.payload_json);
                if (runtime_events.items.len + self.runtime.outbound_messages.items.len >= self.runtime.queue_limits.outbound_messages) {
                    return agent_runtime.RuntimeError.QueueSaturated;
                }
                try runtime_events.append(self.allocator, event);
            }

            const memory_event = try protocol.buildMemoryEvent(self.allocator, "runtime", tick.observe_json);
            if (runtime_events.items.len + self.runtime.outbound_messages.items.len >= self.runtime.queue_limits.outbound_messages) {
                return agent_runtime.RuntimeError.QueueSaturated;
            }
            try runtime_events.append(self.allocator, memory_event);
        }

        return runtime_events.toOwnedSlice(self.allocator);
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

    fn completeWithProvider(self: *RuntimeServer, content: []const u8) ![]u8 {
        const provider = &(self.provider_runtime orelse return RuntimeServerError.ProviderModelNotFound);
        const model = selectModel(provider) orelse return RuntimeServerError.ProviderModelNotFound;

        const api_key = try self.resolveApiKey(provider, model.provider);
        defer self.allocator.free(api_key);

        const user_content = try self.allocator.dupe(u8, content);
        defer self.allocator.free(user_content);
        const messages = try self.allocator.alloc(ziggy_piai.types.Message, 1);
        defer self.allocator.free(messages);
        messages[0] = .{ .role = .user, .content = user_content };

        const context = ziggy_piai.types.Context{ .messages = messages };
        var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(self.allocator);
        defer {
            deinitAssistantEvents(self.allocator, &events);
            events.deinit();
        }

        streamByModelFn(
            self.allocator,
            &provider.http_client,
            &provider.api_registry,
            model,
            context,
            .{ .api_key = api_key },
            &events,
        ) catch return RuntimeServerError.ProviderStreamFailed;

        return extractAssistantText(self.allocator, events.items);
    }

    fn resolveApiKey(self: *RuntimeServer, provider: *const ProviderRuntime, provider_name: []const u8) ![]const u8 {
        if (provider.api_key) |key| return try self.allocator.dupe(u8, key);
        return ziggy_piai.env_api_keys.getEnvApiKey(self.allocator, provider_name) orelse RuntimeServerError.MissingProviderApiKey;
    }

    fn selectModel(provider: *const ProviderRuntime) ?ziggy_piai.types.Model {
        if (provider.model_name) |model_name| {
            return provider.model_registry.getModel(provider.provider_name, model_name);
        }

        for (provider.model_registry.models.items) |model| {
            if (std.mem.eql(u8, model.provider, provider.provider_name)) return model;
        }
        return null;
    }

    fn operationTimeoutNs(self: *const RuntimeServer, operation_class: RuntimeOperationClass) u64 {
        const timeout_ms = switch (operation_class) {
            .chat => self.chat_operation_timeout_ms,
            .control => self.control_operation_timeout_ms,
        };
        return timeout_ms * std.time.ns_per_ms;
    }
};

fn extractAssistantText(allocator: std.mem.Allocator, events: []const ziggy_piai.types.AssistantMessageEvent) ![]u8 {
    var text = std.ArrayListUnmanaged(u8){};
    defer text.deinit(allocator);

    for (events) |event| {
        switch (event) {
            .text_delta => |delta| try text.appendSlice(allocator, delta.delta),
            .done => |done| {
                if (done.text.len > 0) return allocator.dupe(u8, done.text);
            },
            .err => return RuntimeServerError.ProviderStreamFailed,
            else => {},
        }
    }

    return text.toOwnedSlice(allocator);
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

test "runtime_server: session.send dispatches through runtime and emits session.receive" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-1\",\"type\":\"session.send\",\"content\":\"hello runtime\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "hello runtime") != null);
}

test "runtime_server: session.send returns all outbound runtime frames" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-frames\",\"type\":\"session.send\",\"content\":\"hello runtime\"}");
    defer deinitResponseFrames(allocator, responses);

    try std.testing.expect(responses.len >= 3);

    var session_receive_count: usize = 0;
    var tool_event_count: usize = 0;
    var memory_event_count: usize = 0;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"session.receive\"") != null) session_receive_count += 1;
        if (std.mem.indexOf(u8, payload, "\"type\":\"tool.event\"") != null) tool_event_count += 1;
        if (std.mem.indexOf(u8, payload, "\"type\":\"memory.event\"") != null) memory_event_count += 1;
    }

    try std.testing.expect(session_receive_count >= 1);
    try std.testing.expect(tool_event_count >= 1);
    try std.testing.expect(memory_event_count >= 1);
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
}

test "runtime_server: talk enqueue failure rolls back queued user work" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{
        .brain_tick_queue_max = 1,
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
}

test "runtime_server: agent.control pause/resume state" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const pause = try server.handleMessage("{\"id\":\"req-2\",\"type\":\"agent.control\",\"action\":\"pause\"}");
    defer allocator.free(pause);
    try std.testing.expect(std.mem.indexOf(u8, pause, "paused") != null);

    const state = try server.handleMessage("{\"id\":\"req-3\",\"type\":\"agent.control\",\"action\":\"state\"}");
    defer allocator.free(state);
    try std.testing.expect(std.mem.indexOf(u8, state, "paused") != null);

    const resume_resp = try server.handleMessage("{\"id\":\"req-4\",\"type\":\"agent.control\",\"action\":\"resume\"}");
    defer allocator.free(resume_resp);
    try std.testing.expect(std.mem.indexOf(u8, resume_resp, "running") != null);
}

test "runtime_server: paused runtime returns coded runtime_paused error" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const pause = try server.handleMessage("{\"id\":\"req-10\",\"type\":\"agent.control\",\"action\":\"pause\"}");
    defer allocator.free(pause);

    const blocked = try server.handleMessage("{\"id\":\"req-11\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer allocator.free(blocked);

    try std.testing.expect(std.mem.indexOf(u8, blocked, "\"code\":\"runtime_paused\"") != null);
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
