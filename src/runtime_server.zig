const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig");
const protocol = @import("ziggy-spider-protocol").protocol;
const agent_runtime = @import("agent_runtime.zig");
const brain_tools = @import("brain_tools.zig");
const brain_specialization = @import("brain_specialization.zig");
const credential_store = @import("credential_store.zig");
const memory_schema = @import("memory_schema.zig");
const memory = @import("ziggy-memory-store").memory;
const memid = @import("ziggy-memory-store").memid;
const prompt_compiler = @import("prompt_compiler.zig");
const run_engine = @import("run_engine.zig");
const system_hooks = @import("system_hooks.zig");
const tool_registry = @import("ziggy-tool-runtime").tool_registry;
const ziggy_piai = @import("ziggy-piai");

pub const default_agent_id = "default";
const DEFAULT_BRAIN = "primary";
const INTERNAL_TICK_TIMEOUT_MS: i64 = 5 * 1000;
const MAX_PROVIDER_TOOL_ROUNDS: usize = 8;
const MAX_PROVIDER_TOOL_CALLS_PER_TURN: usize = 32;
const MAX_PROVIDER_FOLLOWUP_ROUNDS: usize = 3;
const USE_EXPLICIT_JSON_TOOL_CALLS: bool = false;
const PROVIDER_STREAM_MAX_ATTEMPTS: usize = if (builtin.is_test) 2 else 3;
const PROVIDER_RETRY_BASE_DELAY_MS: u64 = if (builtin.is_test) 1 else 250;
const PROVIDER_RETRY_MAX_DELAY_MS: u64 = if (builtin.is_test) 8 else 4000;
const PROVIDER_RETRY_JITTER_MS: u64 = if (builtin.is_test) 1 else 200;
const BOOTSTRAP_COMPLETE_MEM_NAME = "system.bootstrap.complete";
const BOOTSTRAP_COMPLETE_MEM_KIND = "bootstrap.status";
const BASE_CORE_PROMPT_KIND = "core.base_prompt";
const BASE_CORE_PROMPT_NAME = "core.system.base_instructions";
const CORE_CAPABILITIES_PROMPT_NAME = "core.system.capabilities";
const CORE_IDENTITY_GUIDANCE_PROMPT_NAME = "core.system.identity_guidance";

const RuntimeServerError = error{
    RuntimeTickTimeout,
    RuntimeJobTimeout,
    RuntimeJobCancelled,
    MissingJobResponse,
    ProviderModelNotFound,
    MissingProviderApiKey,
    ProviderStreamFailed,
    ProviderRateLimited,
    ProviderAuthFailed,
    ProviderRequestInvalid,
    ProviderTimeout,
    ProviderUnavailable,
    ProviderToolLoopExceeded,
    RunStepAlreadyActive,
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
    emit_debug: bool = false,
    provider_error_debug_payload: ?[]u8 = null,

    result_mutex: std.Thread.Mutex = .{},
    result_cond: std.Thread.Condition = .{},
    done: bool = false,
    cancelled: bool = false,
    response: ?[][]u8 = null,
};

const ProviderCompletion = struct {
    assistant_text: []u8,
    wait_for_user: bool = false,
    task_complete: bool = false,
    debug_frames: ?[][]u8 = null,

    fn deinit(self: *ProviderCompletion, allocator: std.mem.Allocator) void {
        allocator.free(self.assistant_text);
        if (self.debug_frames) |frames| deinitResponseFrames(allocator, frames);
        self.* = undefined;
    }
};

const RunStepMeta = struct {
    wait_for_user: bool = true,
    task_complete: bool = false,
};

const ProviderToolNameMapEntry = struct {
    provider_name: []u8,
    runtime_name: []const u8,
};

const ProviderLoopAction = enum {
    task_complete,
    followup_needed,
    wait_for_user,
};

const ProviderLoopDirective = struct {
    action: ProviderLoopAction,
    message: ?[]u8 = null,
    reason: []const u8 = "",

    fn deinit(self: *ProviderLoopDirective, allocator: std.mem.Allocator) void {
        if (self.message) |value| allocator.free(value);
        self.* = undefined;
    }
};

const StructuredToolCall = struct {
    id: []u8,
    name: []u8,
    arguments_json: []u8,

    fn deinit(self: *StructuredToolCall, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.arguments_json);
        self.* = undefined;
    }
};

const BootstrapPrompt = struct {
    template_name: []const u8,
    content: []u8,
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
    runs: run_engine.RunEngine,
    provider_runtime: ?ProviderRuntime = null,
    default_agent_id: []u8,
    log_provider_requests: bool = false,

    runtime_mutex: std.Thread.Mutex = .{},
    queue_mutex: std.Thread.Mutex = .{},
    queue_cond: std.Thread.Condition = .{},
    runtime_queue_max: usize = 128,
    chat_operation_timeout_ms: u64 = 120_000,
    control_operation_timeout_ms: u64 = 5_000,
    runtime_jobs: std.ArrayListUnmanaged(*RuntimeQueueJob) = .{},
    run_step_mutex: std.Thread.Mutex = .{},
    active_run_steps: std.StringHashMapUnmanaged(void) = .{},
    cancelled_run_steps: std.StringHashMapUnmanaged(void) = .{},
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

        var runtime = try agent_runtime.AgentRuntime.initWithPersistence(
            allocator,
            agent_id,
            &[_][]const u8{"delegate"},
            effective_ltm_directory,
            effective_ltm_filename,
            runtime_cfg,
        );
        var runtime_owned_by_self = false;
        errdefer if (!runtime_owned_by_self) runtime.deinit();

        var runs = try run_engine.RunEngine.init(
            allocator,
            runtime.ltm_store,
            .{
                .max_run_steps = runtime_cfg.max_run_steps,
                .checkpoint_interval_steps = runtime_cfg.run_checkpoint_interval_steps,
                .run_auto_resume_on_boot = runtime_cfg.run_auto_resume_on_boot,
            },
        );
        var runs_owned_by_self = false;
        errdefer if (!runs_owned_by_self) runs.deinit();

        self.* = .{
            .allocator = allocator,
            .runtime = runtime,
            .runs = runs,
            .runtime_queue_max = runtime_cfg.runtime_request_queue_max,
            .chat_operation_timeout_ms = runtime_cfg.chat_operation_timeout_ms,
            .control_operation_timeout_ms = runtime_cfg.control_operation_timeout_ms,
            .runtime_workers = try allocator.alloc(std.Thread, worker_count),
            .provider_runtime = provider_runtime,
            .default_agent_id = try allocator.dupe(u8, if (runtime_cfg.default_agent_id.len == 0) default_agent_id else runtime_cfg.default_agent_id),
            .log_provider_requests = shouldLogProviderRequests(),
            .test_ltm_directory = test_ltm_directory,
        };
        runtime_owned_by_self = true;
        runs_owned_by_self = true;
        errdefer {
            self.runs.deinit();
            self.runtime.deinit();
            allocator.free(self.runtime_workers);
            allocator.free(self.default_agent_id);
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

        self.run_step_mutex.lock();
        var active_it = self.active_run_steps.iterator();
        while (active_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.active_run_steps.deinit(self.allocator);
        var cancelled_it = self.cancelled_run_steps.iterator();
        while (cancelled_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.cancelled_run_steps.deinit(self.allocator);
        self.run_step_mutex.unlock();

        self.allocator.free(self.runtime_workers);
        self.allocator.free(self.default_agent_id);
        if (self.provider_runtime) |*provider| provider.deinit(self.allocator);
        self.runs.deinit();
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
        return self.handleMessageFramesWithDebug(raw_json, false);
    }

    pub fn handleMessageFramesWithDebug(
        self: *RuntimeServer,
        raw_json: []const u8,
        emit_debug: bool,
    ) ![][]u8 {
        var parsed = parseIncomingMessage(self.allocator, raw_json) catch {
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
                return self.submitRuntimeJobAndAwait(parsed.msg_type, request_id, parsed.content, parsed.action, .chat, emit_debug);
            },
            .agent_run_start, .agent_run_step, .agent_run_resume => {
                return self.submitRuntimeJobAndAwait(parsed.msg_type, request_id, parsed.content, parsed.action, .chat, emit_debug);
            },
            .agent_run_cancel => {
                const run_id = parsed.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        request_id,
                        .missing_content,
                        "agent.run.cancel requires action run_id",
                    ));
                };
                _ = self.requestActiveRunStepCancel(run_id) catch |err| {
                    return self.wrapRuntimeErrorResponse(request_id, err, emit_debug);
                };
                return self.handleRunCancel(request_id, run_id);
            },
            .agent_run_pause, .agent_run_status, .agent_run_events, .agent_run_list => {
                return self.submitRuntimeJobAndAwait(parsed.msg_type, request_id, parsed.content, parsed.action, .control, emit_debug);
            },
            .agent_control => {
                const operation_class: RuntimeOperationClass = if (isChatLikeControlAction(parsed.action)) .chat else .control;
                return self.submitRuntimeJobAndAwait(
                    parsed.msg_type,
                    request_id,
                    parsed.content,
                    parsed.action,
                    operation_class,
                    emit_debug,
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

    fn parseIncomingMessage(allocator: std.mem.Allocator, raw_json: []const u8) !protocol.ParsedMessage {
        return protocol.parseMessage(allocator, raw_json) catch |err| {
            // Be lenient for raw text clients: treat non-JSON-looking payloads as `session.send`.
            const trimmed = std.mem.trim(u8, raw_json, " \t\r\n");
            if (trimmed.len == 0) return err;

            const first = trimmed[0];
            if (first == '{' or first == '[' or first == '"') return err;

            return .{
                .msg_type = .session_send,
                .id = null,
                .content = try allocator.dupe(u8, trimmed),
                .action = null,
            };
        };
    }

    pub fn handleConnectBootstrapFrames(self: *RuntimeServer, request_id: []const u8) ![][]u8 {
        return self.submitRuntimeJobAndAwait(.connect, request_id, null, null, .chat, false);
    }

    fn submitRuntimeJobAndAwait(
        self: *RuntimeServer,
        msg_type: protocol.MessageType,
        request_id: []const u8,
        content: ?[]const u8,
        action: ?[]const u8,
        operation_class: RuntimeOperationClass,
        emit_debug: bool,
    ) ![][]u8 {
        const job = try self.createJob(msg_type, request_id, content, action, emit_debug);
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
                return self.wrapRuntimeTimeoutResponse(request_id, operation_class, emit_debug);
            },
            RuntimeServerError.MissingJobResponse => {
                self.destroyJob(job);
                return self.wrapRuntimeErrorResponse(request_id, err, emit_debug);
            },
            else => {
                self.destroyJob(job);
                return self.wrapRuntimeErrorResponse(request_id, err, emit_debug);
            },
        };
    }

    fn wrapRuntimeTimeoutResponse(
        self: *RuntimeServer,
        request_id: []const u8,
        operation_class: RuntimeOperationClass,
        emit_debug: bool,
    ) ![][]u8 {
        const timeout_ms = self.operationTimeoutNs(operation_class) / std.time.ns_per_ms;
        const queue_depth = self.runtimeQueueDepth();
        std.log.warn(
            "runtime operation timeout request={s} class={s} timeout_ms={d} queue_depth={d}",
            .{ request_id, @tagName(operation_class), timeout_ms, queue_depth },
        );

        if (!emit_debug) {
            return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                self.allocator,
                request_id,
                .runtime_timeout,
                "runtime operation timeout",
            ));
        }

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        const timeout_payload_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"RuntimeJobTimeout\",\"operation_class\":\"{s}\",\"timeout_ms\":{d},\"queue_depth\":{d}}}",
            .{ @tagName(operation_class), timeout_ms, queue_depth },
        );
        defer self.allocator.free(timeout_payload_json);
        try self.appendDebugFrame(&responses, request_id, "runtime.timeout", timeout_payload_json);

        const runtime_error_payload_json = "{\"error\":\"RuntimeJobTimeout\"}";
        try self.appendDebugFrame(&responses, request_id, "runtime.error", runtime_error_payload_json);

        try responses.append(self.allocator, try protocol.buildErrorWithCode(
            self.allocator,
            request_id,
            .runtime_timeout,
            "runtime operation timeout",
        ));
        return responses.toOwnedSlice(self.allocator);
    }

    fn runtimeQueueDepth(self: *RuntimeServer) usize {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();
        return self.runtime_jobs.items.len;
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
                self.destroyJob(job);
            }
        }
    }

    fn processRuntimeJob(self: *RuntimeServer, job: *RuntimeQueueJob) ![][]u8 {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        if (self.isJobCancelled(job)) return RuntimeServerError.RuntimeJobCancelled;

        switch (job.msg_type) {
            .connect => {
                return self.handleConnect(job, job.request_id);
            },
            .session_send => {
                const content = job.content orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "session.send requires content",
                    ));
                };
                return self.handleChat(job, job.request_id, content, null, null);
            },
            .agent_run_start => {
                const content = job.content orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.start requires content",
                    ));
                };
                return self.handleRunStart(job, job.request_id, content);
            },
            .agent_run_step => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.step requires action run_id",
                    ));
                };
                return self.handleRunStep(job, job.request_id, run_id, job.content);
            },
            .agent_run_resume => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.resume requires action run_id",
                    ));
                };
                return self.handleRunResume(job, job.request_id, run_id, job.content);
            },
            .agent_run_pause => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.pause requires action run_id",
                    ));
                };
                return self.handleRunPause(job.request_id, run_id);
            },
            .agent_run_cancel => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.cancel requires action run_id",
                    ));
                };
                return self.handleRunCancel(job.request_id, run_id);
            },
            .agent_run_status => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.status requires action run_id",
                    ));
                };
                return self.handleRunStatus(job.request_id, run_id);
            },
            .agent_run_events => {
                const run_id = job.action orelse {
                    return self.wrapSingleFrame(try protocol.buildErrorWithCode(
                        self.allocator,
                        job.request_id,
                        .missing_content,
                        "agent.run.events requires action run_id",
                    ));
                };
                return self.handleRunEvents(job.request_id, run_id, job.content);
            },
            .agent_run_list => {
                return self.handleRunList(job.request_id);
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

    fn markRunStepActive(self: *RuntimeServer, run_id: []const u8) !bool {
        self.run_step_mutex.lock();
        defer self.run_step_mutex.unlock();

        if (self.active_run_steps.contains(run_id)) return false;
        const owned_key = try self.allocator.dupe(u8, run_id);
        errdefer self.allocator.free(owned_key);
        try self.active_run_steps.put(self.allocator, owned_key, {});
        return true;
    }

    fn isRunStepActive(self: *RuntimeServer, run_id: []const u8) bool {
        self.run_step_mutex.lock();
        defer self.run_step_mutex.unlock();
        return self.active_run_steps.contains(run_id);
    }

    fn clearRunStepTracking(self: *RuntimeServer, run_id: []const u8) void {
        self.run_step_mutex.lock();
        defer self.run_step_mutex.unlock();

        if (self.active_run_steps.fetchRemove(run_id)) |entry| self.allocator.free(entry.key);
        if (self.cancelled_run_steps.fetchRemove(run_id)) |entry| self.allocator.free(entry.key);
    }

    fn requestActiveRunStepCancel(self: *RuntimeServer, run_id: []const u8) !bool {
        self.run_step_mutex.lock();
        defer self.run_step_mutex.unlock();

        if (!self.active_run_steps.contains(run_id)) return false;
        if (!self.cancelled_run_steps.contains(run_id)) {
            const owned_key = try self.allocator.dupe(u8, run_id);
            errdefer self.allocator.free(owned_key);
            try self.cancelled_run_steps.put(self.allocator, owned_key, {});
        }
        return true;
    }

    fn isRunStepCancelRequested(self: *RuntimeServer, run_id: []const u8) bool {
        self.run_step_mutex.lock();
        defer self.run_step_mutex.unlock();
        return self.cancelled_run_steps.contains(run_id);
    }

    fn isExecutionCancelled(self: *RuntimeServer, job: *RuntimeQueueJob, run_id: ?[]const u8) bool {
        if (self.isJobCancelled(job)) return true;
        if (run_id) |value| return self.isRunStepCancelRequested(value);
        return false;
    }

    fn createJob(
        self: *RuntimeServer,
        msg_type: protocol.MessageType,
        request_id: []const u8,
        content: ?[]const u8,
        action: ?[]const u8,
        emit_debug: bool,
    ) !*RuntimeQueueJob {
        const job = try self.allocator.create(RuntimeQueueJob);
        errdefer self.allocator.destroy(job);

        job.* = .{
            .msg_type = msg_type,
            .request_id = try self.allocator.dupe(u8, request_id),
            .content = if (content) |value| try self.allocator.dupe(u8, value) else null,
            .action = if (action) |value| try self.allocator.dupe(u8, value) else null,
            .emit_debug = emit_debug,
        };
        return job;
    }

    fn destroyJob(self: *RuntimeServer, job: *RuntimeQueueJob) void {
        self.allocator.free(job.request_id);
        if (job.content) |owned| self.allocator.free(owned);
        if (job.action) |owned| self.allocator.free(owned);
        if (job.provider_error_debug_payload) |payload| self.allocator.free(payload);
        if (job.response) |frames| deinitResponseFrames(self.allocator, frames);
        self.allocator.destroy(job);
    }

    fn handleConnect(self: *RuntimeServer, job: *RuntimeQueueJob, request_id: []const u8) ![][]u8 {
        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        const bootstrap_prompt = try self.resolveBootstrapPrompt(DEFAULT_BRAIN);
        if (bootstrap_prompt) |prompt| {
            defer self.allocator.free(prompt.content);

            const bootstrap_frames = try self.handleChat(job, request_id, prompt.content, null, null);
            defer deinitResponseFrames(self.allocator, bootstrap_frames);
            for (bootstrap_frames) |frame| {
                try responses.append(self.allocator, try self.allocator.dupe(u8, frame));
            }
            var bootstrap_delivered = false;
            for (bootstrap_frames) |frame| {
                if (std.mem.indexOf(u8, frame, "\"type\":\"session.receive\"") != null) {
                    bootstrap_delivered = true;
                    break;
                }
            }
            if (bootstrap_delivered) {
                self.markBootstrapComplete(DEFAULT_BRAIN, prompt.template_name) catch |err| {
                    std.log.warn("Failed to mark bootstrap complete for {s}: {s}", .{ self.runtime.agent_id, @errorName(err) });
                };
            }
        }

        return responses.toOwnedSlice(self.allocator);
    }

    fn resolveBootstrapPrompt(self: *RuntimeServer, brain_name: []const u8) !?BootstrapPrompt {
        system_hooks.ensureIdentityMemories(&self.runtime, brain_name) catch |err| {
            std.log.warn("Failed to ensure identity memories for {s}: {s}", .{ self.runtime.agent_id, @errorName(err) });
            return null;
        };
        if (try self.hasBootstrapCompleted(brain_name)) return null;

        const template_name = if (std.mem.eql(u8, self.runtime.agent_id, self.default_agent_id))
            "BOOTSTRAP.md"
        else
            "JUST_HATCHED.md";
        std.log.info("Using bootstrap template {s} for {s}/{s}", .{ template_name, self.runtime.agent_id, brain_name });
        const content = system_hooks.readTemplate(self.allocator, &self.runtime, template_name) catch |err| {
            std.log.warn("Failed to load bootstrap template {s}: {s}", .{ template_name, @errorName(err) });
            return null;
        };
        return .{
            .template_name = template_name,
            .content = content,
        };
    }

    fn hasBootstrapCompleted(self: *RuntimeServer, brain_name: []const u8) !bool {
        var item = (try self.loadMemoryByName(brain_name, BOOTSTRAP_COMPLETE_MEM_NAME)) orelse return false;
        item.deinit(self.allocator);
        return true;
    }

    fn markBootstrapComplete(self: *RuntimeServer, brain_name: []const u8, template_name: []const u8) !void {
        const escaped_template = try protocol.jsonEscape(self.allocator, template_name);
        defer self.allocator.free(escaped_template);

        const payload = try std.fmt.allocPrint(
            self.allocator,
            "{{\"complete\":true,\"template\":\"{s}\",\"completed_at_ms\":{d}}}",
            .{ escaped_template, std.time.milliTimestamp() },
        );
        defer self.allocator.free(payload);

        if (try self.loadMemoryByName(brain_name, BOOTSTRAP_COMPLETE_MEM_NAME)) |existing_item| {
            var item = existing_item;
            defer item.deinit(self.allocator);
            var mutated = try self.runtime.active_memory.mutate(item.mem_id, payload);
            mutated.deinit(self.allocator);
            return;
        }

        var created = try self.runtime.active_memory.create(
            brain_name,
            BOOTSTRAP_COMPLETE_MEM_NAME,
            BOOTSTRAP_COMPLETE_MEM_KIND,
            payload,
            false,
            true,
        );
        created.deinit(self.allocator);
    }

    fn loadMemoryByName(self: *RuntimeServer, brain_name: []const u8, name: []const u8) !?memory.ActiveMemoryItem {
        const mem_id = try self.buildLatestMemId(brain_name, name);
        defer self.allocator.free(mem_id);

        return self.runtime.active_memory.load(mem_id, null) catch |err| switch (err) {
            memory.MemoryError.NotFound => null,
            else => err,
        };
    }

    fn buildLatestMemId(self: *RuntimeServer, brain_name: []const u8, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}{s}:{s}:{s}:latest{s}",
            .{ memid.EOT_MARKER, self.runtime.agent_id, brain_name, name, memid.EOT_MARKER },
        );
    }

    fn handleChat(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        content: []const u8,
        run_step_meta: ?*RunStepMeta,
        run_id: ?[]const u8,
    ) ![][]u8 {
        if (run_step_meta) |meta| {
            meta.* = .{};
        }
        if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;
        system_hooks.ensureIdentityMemories(&self.runtime, DEFAULT_BRAIN) catch |err| {
            std.log.warn("Failed to ensure identity memories for {s}: {s}", .{ self.runtime.agent_id, @errorName(err) });
        };
        memory_schema.ensureRuntimeInstructionMemories(&self.runtime, DEFAULT_BRAIN) catch |err| {
            std.log.warn("Failed to ensure runtime instruction memories for {s}: {s}", .{ self.runtime.agent_id, @errorName(err) });
        };
        memory_schema.setActiveGoal(&self.runtime, DEFAULT_BRAIN, content) catch |err| {
            std.log.warn("Failed to update active goal memory for {s}: {s}", .{ self.runtime.agent_id, @errorName(err) });
        };

        self.runtime.appendMessageMemory(DEFAULT_BRAIN, "user", content) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };

        var provider_completion = if (self.provider_runtime != null)
            self.completeWithProvider(job, DEFAULT_BRAIN, run_id) catch |err| return self.wrapRuntimeErrorResponseWithProviderDebug(job, request_id, err, job.emit_debug)
        else
            ProviderCompletion{
                .assistant_text = try self.allocator.dupe(u8, content),
            };
        defer provider_completion.deinit(self.allocator);

        if (run_step_meta) |meta| {
            meta.wait_for_user = if (self.provider_runtime != null) provider_completion.wait_for_user else true;
            meta.task_complete = provider_completion.task_complete;
        }

        if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;

        if (!provider_completion.wait_for_user) {
            const escaped_content = try protocol.jsonEscape(self.allocator, provider_completion.assistant_text);
            defer self.allocator.free(escaped_content);
            const talk_args = try std.fmt.allocPrint(self.allocator, "{{\"message\":\"{s}\"}}", .{escaped_content});
            defer self.allocator.free(talk_args);
            self.runtime.queueToolUse(DEFAULT_BRAIN, "talk_user", talk_args) catch |err| {
                return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
            };

            self.runPendingTicks(job, run_id, null) catch |err| {
                self.clearRuntimeOutboundLocked();
                if (err == RuntimeServerError.RuntimeJobCancelled) return err;
                return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
            };
        }

        if (provider_completion.assistant_text.len > 0) {
            self.runtime.appendMessageMemory(DEFAULT_BRAIN, "assistant", provider_completion.assistant_text) catch |err| {
                self.clearRuntimeOutboundLocked();
                return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
            };
        }

        const outbound = try self.runtime.drainOutbound(self.allocator);
        defer agent_runtime.deinitOutbound(self.allocator, outbound);

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        if (provider_completion.debug_frames) |debug_frames| {
            for (debug_frames) |payload| {
                try responses.append(self.allocator, try self.allocator.dupe(u8, payload));
            }
        }

        if (outbound.len == 0) {
            const fallback_text = if (provider_completion.assistant_text.len > 0)
                provider_completion.assistant_text
            else
                "ok";
            try responses.append(self.allocator, try protocol.buildSessionReceive(self.allocator, request_id, fallback_text));
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
            return self.handleChat(job, request_id, goal, null, null);
        }

        return self.wrapSingleFrame(try protocol.buildErrorWithCode(
            self.allocator,
            request_id,
            .unsupported_message_type,
            "unsupported agent.control action in chat-only mode",
        ));
    }

    fn handleRunStart(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        content: []const u8,
    ) ![][]u8 {
        var started = self.runs.start(content) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };
        defer started.deinit(self.allocator);
        return self.runSingleStep(job, request_id, started.run_id, null, true, false);
    }

    fn handleRunStep(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        run_id: []const u8,
        content: ?[]const u8,
    ) ![][]u8 {
        return self.runSingleStep(job, request_id, run_id, content, false, false);
    }

    fn handleRunResume(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        run_id: []const u8,
        content: ?[]const u8,
    ) ![][]u8 {
        return self.runSingleStep(job, request_id, run_id, content, false, true);
    }

    fn handleRunPause(self: *RuntimeServer, request_id: []const u8, run_id: []const u8) ![][]u8 {
        if (self.isRunStepActive(run_id)) {
            return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, RuntimeServerError.RunStepAlreadyActive));
        }
        var snapshot = self.runs.pause(run_id) catch |err| return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        defer snapshot.deinit(self.allocator);
        return self.wrapSingleFrame(try protocol.buildAgentRunState(
            self.allocator,
            request_id,
            snapshot.run_id,
            @tagName(snapshot.state),
            snapshot.step_count,
            snapshot.checkpoint_seq,
        ));
    }

    fn handleRunCancel(self: *RuntimeServer, request_id: []const u8, run_id: []const u8) ![][]u8 {
        var snapshot = self.runs.cancel(run_id) catch |err| return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        defer snapshot.deinit(self.allocator);
        return self.wrapSingleFrame(try protocol.buildAgentRunState(
            self.allocator,
            request_id,
            snapshot.run_id,
            @tagName(snapshot.state),
            snapshot.step_count,
            snapshot.checkpoint_seq,
        ));
    }

    fn handleRunStatus(self: *RuntimeServer, request_id: []const u8, run_id: []const u8) ![][]u8 {
        var snapshot = self.runs.get(run_id) catch |err| return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        defer snapshot.deinit(self.allocator);
        return self.wrapSingleFrame(try protocol.buildAgentRunState(
            self.allocator,
            request_id,
            snapshot.run_id,
            @tagName(snapshot.state),
            snapshot.step_count,
            snapshot.checkpoint_seq,
        ));
    }

    fn handleRunList(self: *RuntimeServer, request_id: []const u8) ![][]u8 {
        const snapshots = self.runs.list(self.allocator) catch |err| return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        defer run_engine.deinitSnapshots(self.allocator, snapshots);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"runs\":[");

        for (snapshots, 0..) |snapshot, idx| {
            if (idx > 0) try payload.append(self.allocator, ',');
            try payload.writer(self.allocator).print(
                "{{\"run_id\":\"{s}\",\"state\":\"{s}\",\"step_count\":{d},\"checkpoint_seq\":{d},\"updated_at_ms\":{d}}}",
                .{
                    snapshot.run_id,
                    @tagName(snapshot.state),
                    snapshot.step_count,
                    snapshot.checkpoint_seq,
                    snapshot.updated_at_ms,
                },
            );
        }
        try payload.appendSlice(self.allocator, "]}");
        const payload_json = try payload.toOwnedSlice(self.allocator);
        defer self.allocator.free(payload_json);

        return self.wrapSingleFrame(try protocol.buildAgentRunEvent(
            self.allocator,
            request_id,
            "all",
            "run.list",
            payload_json,
        ));
    }

    fn handleRunEvents(
        self: *RuntimeServer,
        request_id: []const u8,
        run_id: []const u8,
        content: ?[]const u8,
    ) ![][]u8 {
        const limit = blk: {
            if (content) |value| {
                const parsed = std.fmt.parseUnsigned(usize, value, 10) catch break :blk @as(usize, 50);
                if (parsed == 0) break :blk @as(usize, 50);
                break :blk @min(parsed, 500);
            }
            break :blk @as(usize, 50);
        };
        const events = self.runs.listEvents(self.allocator, run_id, limit) catch |err| return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        defer run_engine.deinitEvents(self.allocator, events);

        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"events\":[");
        for (events, 0..) |event, idx| {
            if (idx > 0) try payload.append(self.allocator, ',');
            try payload.writer(self.allocator).print(
                "{{\"seq\":{d},\"event_type\":\"{s}\",\"created_at_ms\":{d},\"payload\":{s}}}",
                .{ event.seq, event.event_type, event.created_at_ms, event.payload_json },
            );
        }
        try payload.appendSlice(self.allocator, "]}");
        const payload_json = try payload.toOwnedSlice(self.allocator);
        defer self.allocator.free(payload_json);

        return self.wrapSingleFrame(try protocol.buildAgentRunEvent(
            self.allocator,
            request_id,
            run_id,
            "run.events",
            payload_json,
        ));
    }

    fn runSingleStep(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        run_id: []const u8,
        content: ?[]const u8,
        include_ack: bool,
        allow_paused_resume: bool,
    ) ![][]u8 {
        const owns_step_tracking = self.markRunStepActive(run_id) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };
        if (!owns_step_tracking) {
            return self.wrapRuntimeErrorResponse(request_id, RuntimeServerError.RunStepAlreadyActive, job.emit_debug);
        }
        defer if (owns_step_tracking) self.clearRunStepTracking(run_id);

        if (self.isRunStepCancelRequested(run_id)) {
            _ = self.runs.cancel(run_id) catch {};
            return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
        }

        var work = (if (allow_paused_resume) self.runs.beginResumedStep(run_id, content) else self.runs.beginStep(run_id, content)) catch |err| {
            if (err == run_engine.RunEngineError.InvalidState and self.isRunStepCancelRequested(run_id)) {
                _ = self.runs.cancel(run_id) catch {};
                return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
            }
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };
        defer work.deinit(self.allocator);

        const observe_payload = try std.fmt.allocPrint(self.allocator, "{{\"step\":{d}}}", .{work.step_count});
        defer self.allocator.free(observe_payload);
        self.runs.recordPhase(run_id, .observe, observe_payload) catch |err| {
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };

        var chat_meta = RunStepMeta{};
        const chat_frames = self.handleChat(job, request_id, work.input, &chat_meta, run_id) catch |err| {
            if (err == RuntimeServerError.RuntimeJobCancelled) {
                if (self.isRunStepCancelRequested(run_id)) {
                    _ = self.runs.cancel(run_id) catch {};
                    return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
                }
                _ = self.runs.abortStep(run_id, "runtime_job_cancelled", true) catch {};
                return err;
            }
            _ = self.runs.failStep(run_id, @errorName(err)) catch {};
            return err;
        };
        defer deinitResponseFrames(self.allocator, chat_frames);

        if (self.isRunStepCancelRequested(run_id)) {
            _ = self.runs.cancel(run_id) catch {};
            return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
        }
        if (self.isJobCancelled(job)) {
            _ = self.runs.abortStep(run_id, "runtime_job_cancelled", true) catch {};
            return RuntimeServerError.RuntimeJobCancelled;
        }

        var extracted = try extractRunStepFrameResult(self.allocator, chat_frames);
        defer extracted.deinit(self.allocator);

        if (extracted.error_message) |error_message| {
            var failed = self.runs.failStep(run_id, error_message) catch |err| {
                return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
            };
            defer failed.deinit(self.allocator);

            var responses = std.ArrayListUnmanaged([]u8){};
            errdefer {
                for (responses.items) |payload| self.allocator.free(payload);
                responses.deinit(self.allocator);
            }

            if (include_ack) {
                try responses.append(self.allocator, try protocol.buildAgentRunAck(
                    self.allocator,
                    request_id,
                    failed.run_id,
                    @tagName(failed.state),
                    failed.step_count,
                    failed.checkpoint_seq,
                ));
            }

            for (chat_frames) |payload| {
                try responses.append(self.allocator, try self.allocator.dupe(u8, payload));
            }

            try responses.append(self.allocator, try protocol.buildAgentRunState(
                self.allocator,
                request_id,
                failed.run_id,
                @tagName(failed.state),
                failed.step_count,
                failed.checkpoint_seq,
            ));
            return responses.toOwnedSlice(self.allocator);
        }

        const assistant_output = extracted.assistant_content;
        const wait_for_user = chat_meta.wait_for_user;
        const completion_output = if (chat_meta.task_complete and !containsCaseInsensitive(assistant_output, "task_complete"))
            try buildTaskCompleteOutput(self.allocator, assistant_output)
        else
            try self.allocator.dupe(u8, assistant_output);
        defer self.allocator.free(completion_output);

        if (self.isRunStepCancelRequested(run_id)) {
            _ = self.runs.cancel(run_id) catch {};
            return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
        }
        if (self.isJobCancelled(job)) {
            _ = self.runs.abortStep(run_id, "runtime_job_cancelled", true) catch {};
            return RuntimeServerError.RuntimeJobCancelled;
        }

        self.runs.recordPhase(run_id, .decide, "{}") catch |err| return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        self.runs.recordPhase(run_id, .act, "{}") catch |err| return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        self.runs.recordPhase(run_id, .integrate, "{}") catch |err| return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        self.runs.recordPhase(run_id, .checkpoint, "{}") catch |err| return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);

        if (builtin.is_test) {
            if (testBeforeCompleteStepHook) |hook| {
                hook(self, run_id) catch |err| {
                    return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
                };
            }
        }

        var completed = self.runs.completeStep(run_id, completion_output, wait_for_user, chat_meta.task_complete) catch |err| {
            if (err == run_engine.RunEngineError.InvalidState) {
                if (self.isRunStepCancelRequested(run_id)) {
                    _ = self.runs.cancel(run_id) catch {};
                    return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
                }

                var snapshot = self.runs.get(run_id) catch {
                    return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
                };
                defer snapshot.deinit(self.allocator);
                if (snapshot.state == .cancelled) {
                    return self.wrapRuntimeErrorResponse(request_id, agent_runtime.RuntimeError.RuntimeCancelled, job.emit_debug);
                }
            }
            return self.wrapRuntimeErrorResponse(request_id, err, job.emit_debug);
        };
        defer completed.deinit(self.allocator);

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        if (include_ack) {
            try responses.append(self.allocator, try protocol.buildAgentRunAck(
                self.allocator,
                request_id,
                completed.run_id,
                @tagName(completed.state),
                completed.step_count,
                completed.checkpoint_seq,
            ));
        }

        const escaped_output = try protocol.jsonEscape(self.allocator, assistant_output);
        defer self.allocator.free(escaped_output);
        const event_payload = try std.fmt.allocPrint(self.allocator, "{{\"step\":{d},\"assistant\":\"{s}\"}}", .{ completed.step_count, escaped_output });
        defer self.allocator.free(event_payload);
        try responses.append(self.allocator, try protocol.buildAgentRunEvent(
            self.allocator,
            request_id,
            completed.run_id,
            "assistant.output",
            event_payload,
        ));

        try responses.append(self.allocator, try protocol.buildAgentRunState(
            self.allocator,
            request_id,
            completed.run_id,
            @tagName(completed.state),
            completed.step_count,
            completed.checkpoint_seq,
        ));

        return responses.toOwnedSlice(self.allocator);
    }

    const RunStepFrameResult = struct {
        assistant_content: []u8,
        error_message: ?[]u8 = null,

        fn deinit(self: *RunStepFrameResult, allocator: std.mem.Allocator) void {
            allocator.free(self.assistant_content);
            if (self.error_message) |message| allocator.free(message);
            self.* = undefined;
        }
    };

    fn extractRunStepFrameResult(allocator: std.mem.Allocator, frames: [][]u8) !RunStepFrameResult {
        var assistant_content: ?[]u8 = null;
        errdefer if (assistant_content) |value| allocator.free(value);
        var error_message: ?[]u8 = null;
        errdefer if (error_message) |value| allocator.free(value);

        for (frames) |frame| {
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, frame, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;

            const msg_type = if (parsed.value.object.get("type")) |value|
                if (value == .string) value.string else ""
            else
                "";
            if (std.mem.eql(u8, msg_type, "session.receive")) {
                const content = if (parsed.value.object.get("content")) |value|
                    if (value == .string) value.string else ""
                else
                    "";
                const latest = try allocator.dupe(u8, content);
                if (assistant_content) |previous| allocator.free(previous);
                assistant_content = latest;
                continue;
            }

            if (std.mem.eql(u8, msg_type, "error")) {
                if (error_message == null) {
                    const message = if (parsed.value.object.get("message")) |value|
                        if (value == .string) value.string else "runtime error"
                    else
                        "runtime error";
                    error_message = try allocator.dupe(u8, message);
                }
            }
        }

        return .{
            .assistant_content = if (assistant_content) |value| value else try allocator.dupe(u8, ""),
            .error_message = error_message,
        };
    }

    fn runPendingTicks(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        run_id: ?[]const u8,
        tool_payloads: ?*std.ArrayListUnmanaged([]u8),
    ) !void {
        const started_ms = std.time.milliTimestamp();

        while (true) {
            if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;

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
            RuntimeServerError.ProviderRateLimited => protocol.buildErrorWithCode(self.allocator, request_id, .provider_rate_limited, "provider rate limited"),
            RuntimeServerError.ProviderAuthFailed => protocol.buildErrorWithCode(self.allocator, request_id, .provider_auth_failed, "provider authentication failed"),
            RuntimeServerError.ProviderRequestInvalid => protocol.buildErrorWithCode(self.allocator, request_id, .provider_request_invalid, "provider request invalid"),
            RuntimeServerError.ProviderTimeout => protocol.buildErrorWithCode(self.allocator, request_id, .provider_timeout, "provider request timed out"),
            RuntimeServerError.ProviderUnavailable => protocol.buildErrorWithCode(self.allocator, request_id, .provider_unavailable, "provider temporarily unavailable"),
            RuntimeServerError.ProviderStreamFailed => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "provider stream failed"),
            RuntimeServerError.ProviderToolLoopExceeded => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "provider tool loop exceeded limits"),
            RuntimeServerError.RunStepAlreadyActive => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, "run step already active"),
            else => protocol.buildErrorWithCode(self.allocator, request_id, .execution_failed, @errorName(err)),
        };
    }

    fn wrapRuntimeErrorResponse(
        self: *RuntimeServer,
        request_id: []const u8,
        err: anyerror,
        emit_debug: bool,
    ) ![][]u8 {
        if (!emit_debug) return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        const error_name = @errorName(err);
        const escaped_error = try protocol.jsonEscape(self.allocator, error_name);
        defer self.allocator.free(escaped_error);
        const debug_payload_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"{s}\"}}",
            .{escaped_error},
        );
        defer self.allocator.free(debug_payload_json);

        try self.appendDebugFrame(
            &responses,
            request_id,
            "runtime.error",
            debug_payload_json,
        );
        try responses.append(self.allocator, try self.buildRuntimeErrorResponse(request_id, err));
        return responses.toOwnedSlice(self.allocator);
    }

    fn wrapRuntimeErrorResponseWithProviderDebug(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        request_id: []const u8,
        err: anyerror,
        emit_debug: bool,
    ) ![][]u8 {
        const provider_error_payload = job.provider_error_debug_payload;
        job.provider_error_debug_payload = null;

        if (!emit_debug) {
            if (provider_error_payload) |payload| self.allocator.free(payload);
            return self.wrapSingleFrame(try self.buildRuntimeErrorResponse(request_id, err));
        }

        var responses = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (responses.items) |payload| self.allocator.free(payload);
            responses.deinit(self.allocator);
        }

        if (provider_error_payload) |payload| {
            defer self.allocator.free(payload);
            try self.appendDebugFrame(
                &responses,
                request_id,
                "provider.error",
                payload,
            );
        }

        const error_name = @errorName(err);
        const escaped_error = try protocol.jsonEscape(self.allocator, error_name);
        defer self.allocator.free(escaped_error);
        const debug_payload_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":\"{s}\"}}",
            .{escaped_error},
        );
        defer self.allocator.free(debug_payload_json);

        try self.appendDebugFrame(
            &responses,
            request_id,
            "runtime.error",
            debug_payload_json,
        );
        try responses.append(self.allocator, try self.buildRuntimeErrorResponse(request_id, err));
        return responses.toOwnedSlice(self.allocator);
    }

    fn setProviderErrorDebugPayload(self: *RuntimeServer, job: *RuntimeQueueJob, payload_json: []const u8) !void {
        if (job.provider_error_debug_payload) |existing| self.allocator.free(existing);
        job.provider_error_debug_payload = try self.allocator.dupe(u8, payload_json);
    }

    fn wrapSingleFrame(self: *RuntimeServer, payload: []u8) ![][]u8 {
        const frames = try self.allocator.alloc([]u8, 1);
        frames[0] = payload;
        return frames;
    }

    fn appendDebugFrame(
        self: *RuntimeServer,
        frames: *std.ArrayListUnmanaged([]u8),
        request_id: []const u8,
        category: []const u8,
        payload_json: []const u8,
    ) !void {
        const redacted_payload = try redactDebugPayload(self.allocator, payload_json);
        defer self.allocator.free(redacted_payload);

        const payload = try protocol.buildDebugEvent(
            self.allocator,
            request_id,
            category,
            redacted_payload,
        );
        try frames.append(self.allocator, payload);
    }

    fn buildProviderRequestDebugPayload(
        self: *RuntimeServer,
        brain_name: []const u8,
        model: ziggy_piai.types.Model,
        context: ziggy_piai.types.Context,
        options: ziggy_piai.types.StreamOptions,
        round: usize,
    ) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        const escaped_brain = try protocol.jsonEscape(self.allocator, brain_name);
        defer self.allocator.free(escaped_brain);
        const escaped_provider = try protocol.jsonEscape(self.allocator, model.provider);
        defer self.allocator.free(escaped_provider);
        const escaped_model = try protocol.jsonEscape(self.allocator, model.id);
        defer self.allocator.free(escaped_model);
        const escaped_system_prompt = try protocol.jsonEscape(self.allocator, context.system_prompt orelse "");
        defer self.allocator.free(escaped_system_prompt);

        try out.appendSlice(self.allocator, "{\"brain\":\"");
        try out.appendSlice(self.allocator, escaped_brain);
        try out.appendSlice(self.allocator, "\",\"provider\":\"");
        try out.appendSlice(self.allocator, escaped_provider);
        try out.appendSlice(self.allocator, "\",\"model\":\"");
        try out.appendSlice(self.allocator, escaped_model);
        try out.appendSlice(self.allocator, "\",\"round\":");
        try out.writer(self.allocator).print("{d}", .{round + 1});
        try out.appendSlice(self.allocator, ",\"system_prompt\":\"");
        try out.appendSlice(self.allocator, escaped_system_prompt);
        try out.appendSlice(self.allocator, "\",\"messages\":[");

        for (context.messages, 0..) |message, idx| {
            if (idx > 0) try out.append(self.allocator, ',');
            const escaped_content = try protocol.jsonEscape(self.allocator, message.content);
            defer self.allocator.free(escaped_content);
            try out.appendSlice(self.allocator, "{\"role\":\"");
            try out.appendSlice(self.allocator, @tagName(message.role));
            try out.appendSlice(self.allocator, "\",\"content\":\"");
            try out.appendSlice(self.allocator, escaped_content);
            try out.appendSlice(self.allocator, "\"}");
        }

        try out.appendSlice(self.allocator, "],\"tools\":[");
        const tools = context.tools orelse &.{};
        for (tools, 0..) |tool, idx| {
            if (idx > 0) try out.append(self.allocator, ',');
            const escaped_name = try protocol.jsonEscape(self.allocator, tool.name);
            defer self.allocator.free(escaped_name);
            const escaped_desc = try protocol.jsonEscape(self.allocator, tool.description);
            defer self.allocator.free(escaped_desc);
            const escaped_params = try protocol.jsonEscape(self.allocator, tool.parameters_json);
            defer self.allocator.free(escaped_params);
            try out.appendSlice(self.allocator, "{\"name\":\"");
            try out.appendSlice(self.allocator, escaped_name);
            try out.appendSlice(self.allocator, "\",\"description\":\"");
            try out.appendSlice(self.allocator, escaped_desc);
            try out.appendSlice(self.allocator, "\",\"parameters_json\":\"");
            try out.appendSlice(self.allocator, escaped_params);
            try out.appendSlice(self.allocator, "\"}");
        }

        const escaped_reasoning = try protocol.jsonEscape(self.allocator, options.reasoning orelse "");
        defer self.allocator.free(escaped_reasoning);
        const escaped_api_key = try protocol.jsonEscape(self.allocator, options.api_key orelse "");
        defer self.allocator.free(escaped_api_key);
        try out.appendSlice(self.allocator, "],\"options\":{\"reasoning\":\"");
        try out.appendSlice(self.allocator, escaped_reasoning);
        try out.appendSlice(self.allocator, "\",\"api_key\":\"");
        try out.appendSlice(self.allocator, escaped_api_key);
        try out.appendSlice(self.allocator, "\"}}");

        return out.toOwnedSlice(self.allocator);
    }

    fn buildProviderResponseDebugPayload(
        self: *RuntimeServer,
        assistant: ziggy_piai.types.AssistantMessage,
        round: usize,
    ) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        const escaped_text = try protocol.jsonEscape(self.allocator, assistant.text);
        defer self.allocator.free(escaped_text);
        const stop_reason = @tagName(assistant.stop_reason);
        const escaped_stop = try protocol.jsonEscape(self.allocator, stop_reason);
        defer self.allocator.free(escaped_stop);

        try out.appendSlice(self.allocator, "{\"round\":");
        try out.writer(self.allocator).print("{d}", .{round + 1});
        try out.appendSlice(self.allocator, ",\"stop_reason\":\"");
        try out.appendSlice(self.allocator, escaped_stop);
        try out.appendSlice(self.allocator, "\",\"text\":\"");
        try out.appendSlice(self.allocator, escaped_text);
        try out.appendSlice(self.allocator, "\",\"tool_calls\":[");

        for (assistant.tool_calls, 0..) |tool_call, idx| {
            if (idx > 0) try out.append(self.allocator, ',');
            const escaped_id = try protocol.jsonEscape(self.allocator, tool_call.id);
            defer self.allocator.free(escaped_id);
            const escaped_name = try protocol.jsonEscape(self.allocator, tool_call.name);
            defer self.allocator.free(escaped_name);
            const normalized_args = try normalizeJsonValueForDebug(self.allocator, tool_call.arguments_json);
            defer self.allocator.free(normalized_args);

            try out.appendSlice(self.allocator, "{\"id\":\"");
            try out.appendSlice(self.allocator, escaped_id);
            try out.appendSlice(self.allocator, "\",\"name\":\"");
            try out.appendSlice(self.allocator, escaped_name);
            try out.appendSlice(self.allocator, "\",\"arguments\":");
            try out.appendSlice(self.allocator, normalized_args);
            try out.appendSlice(self.allocator, "}");
        }

        try out.appendSlice(self.allocator, "]}");
        return out.toOwnedSlice(self.allocator);
    }

    fn buildProviderToolCallDebugPayload(
        self: *RuntimeServer,
        tool_call: ziggy_piai.types.ToolCall,
        runtime_tool_name: []const u8,
        args_with_call_id: []const u8,
        round: usize,
    ) ![]u8 {
        const escaped_provider_name = try protocol.jsonEscape(self.allocator, tool_call.name);
        defer self.allocator.free(escaped_provider_name);
        const escaped_runtime_name = try protocol.jsonEscape(self.allocator, runtime_tool_name);
        defer self.allocator.free(escaped_runtime_name);
        const escaped_call_id = try protocol.jsonEscape(self.allocator, tool_call.id);
        defer self.allocator.free(escaped_call_id);
        const normalized_args = try normalizeJsonValueForDebug(self.allocator, args_with_call_id);
        defer self.allocator.free(normalized_args);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"round\":{d},\"call_id\":\"{s}\",\"provider_tool_name\":\"{s}\",\"runtime_tool_name\":\"{s}\",\"arguments\":{s}}}",
            .{ round + 1, escaped_call_id, escaped_provider_name, escaped_runtime_name, normalized_args },
        );
    }

    fn buildProviderErrorDebugPayload(
        self: *RuntimeServer,
        model: ziggy_piai.types.Model,
        error_text: []const u8,
        mapped_error: RuntimeServerError,
        retryable: bool,
        source: []const u8,
    ) ![]u8 {
        const escaped_provider = try protocol.jsonEscape(self.allocator, model.provider);
        defer self.allocator.free(escaped_provider);
        const escaped_model = try protocol.jsonEscape(self.allocator, model.id);
        defer self.allocator.free(escaped_model);
        const escaped_error = try protocol.jsonEscape(self.allocator, error_text);
        defer self.allocator.free(escaped_error);
        const escaped_mapped = try protocol.jsonEscape(self.allocator, @errorName(mapped_error));
        defer self.allocator.free(escaped_mapped);
        const escaped_source = try protocol.jsonEscape(self.allocator, source);
        defer self.allocator.free(escaped_source);

        return std.fmt.allocPrint(
            self.allocator,
            "{{\"provider\":\"{s}\",\"model\":\"{s}\",\"error\":\"{s}\",\"mapped_error\":\"{s}\",\"retryable\":{},\"source\":\"{s}\"}}",
            .{ escaped_provider, escaped_model, escaped_error, escaped_mapped, retryable, escaped_source },
        );
    }

    const ProviderFailure = struct {
        runtime_error: RuntimeServerError,
        retryable: bool,
        retry_after_ms: ?u64 = null,
    };

    fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
        return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
    }

    fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
        for (needles) |needle| {
            if (containsIgnoreCase(haystack, needle)) return true;
        }
        return false;
    }

    fn parseFirstUnsigned(input: []const u8) ?u64 {
        var start: ?usize = null;
        for (input, 0..) |ch, idx| {
            if (ch >= '0' and ch <= '9') {
                start = idx;
                break;
            }
        }
        const first = start orelse return null;

        var value: u64 = 0;
        var saw_digit = false;
        var i = first;
        while (i < input.len) : (i += 1) {
            const ch = input[i];
            if (ch < '0' or ch > '9') break;
            saw_digit = true;
            const digit: u64 = @intCast(ch - '0');
            if (value > (std.math.maxInt(u64) - digit) / 10) return null;
            value = (value * 10) + digit;
        }
        if (!saw_digit) return null;
        return value;
    }

    fn parseRetryAfterMs(provider_error_message: []const u8) ?u64 {
        const markers = [_][]const u8{
            "retry-after:",
            "retry after",
            "try again in",
        };
        for (markers) |marker| {
            const marker_idx = std.ascii.indexOfIgnoreCase(provider_error_message, marker) orelse continue;
            const tail = provider_error_message[marker_idx + marker.len ..];
            const amount = parseFirstUnsigned(tail) orelse continue;
            const window_len: usize = if (tail.len < 40) tail.len else 40;
            const window = tail[0..window_len];

            if (containsIgnoreCase(window, "ms")) return amount;
            if (containsAnyIgnoreCase(window, &.{ "min", "minute" })) {
                return std.math.mul(u64, amount, 60_000) catch PROVIDER_RETRY_MAX_DELAY_MS;
            }
            return std.math.mul(u64, amount, 1_000) catch PROVIDER_RETRY_MAX_DELAY_MS;
        }
        return null;
    }

    fn classifyProviderFailure(stream_error_name: ?[]const u8, provider_error_message: ?[]const u8) ProviderFailure {
        const err_name = stream_error_name orelse "";
        const message = provider_error_message orelse "";

        if (containsAnyIgnoreCase(err_name, &.{ "MissingApiKey", "MissingProviderApiKey" })) {
            return .{ .runtime_error = RuntimeServerError.MissingProviderApiKey, .retryable = false };
        }

        if (containsAnyIgnoreCase(message, &.{ "429", "rate limit", "too many requests", "usage limit", "quota exceeded" })) {
            return .{
                .runtime_error = RuntimeServerError.ProviderRateLimited,
                .retryable = true,
                .retry_after_ms = parseRetryAfterMs(message),
            };
        }

        if (containsAnyIgnoreCase(message, &.{ "401", "403", "unauthorized", "forbidden", "invalid api key", "invalid_api_key", "invalid token", "token expired", "insufficient permission", "permission denied" }) or
            containsAnyIgnoreCase(err_name, &.{ "Unauthorized", "Forbidden", "Auth", "InvalidApiKey", "InvalidCodexApiKey", "TokenExchangeFailed" }))
        {
            return .{ .runtime_error = RuntimeServerError.ProviderAuthFailed, .retryable = false };
        }

        if (containsAnyIgnoreCase(message, &.{ "400", "404", "422", "bad request", "invalid request", "invalid schema", "schema missing", "model not found", "unsupported model", "unknown model", "unrecognized request argument", "invalid request envelope" }) or
            containsAnyIgnoreCase(err_name, &.{ "BadRequest", "InvalidRequest", "ModelNotFound", "ProviderNotRegistered", "ProviderNotSupported" }))
        {
            return .{ .runtime_error = RuntimeServerError.ProviderRequestInvalid, .retryable = false };
        }

        if (containsAnyIgnoreCase(message, &.{ "timeout", "timed out", "deadline exceeded", "request timeout" }) or
            containsAnyIgnoreCase(err_name, &.{ "Timeout", "TimedOut" }))
        {
            return .{ .runtime_error = RuntimeServerError.ProviderTimeout, .retryable = true };
        }

        if (containsAnyIgnoreCase(message, &.{ "500", "502", "503", "504", "service unavailable", "temporarily unavailable", "connection reset", "connection refused", "broken pipe", "end of stream", "network error", "connection closed", "econnreset", "writefailed", "write failed", "readfailed", "read failed" }) or
            containsAnyIgnoreCase(err_name, &.{ "ConnectionResetByPeer", "ConnectionRefused", "ConnectionClosed", "NetworkUnreachable", "HostUnreachable", "BrokenPipe", "EndOfStream", "MockProviderUnavailable", "Tls", "WriteFailed", "ReadFailed" }))
        {
            return .{ .runtime_error = RuntimeServerError.ProviderUnavailable, .retryable = true };
        }

        if (containsAnyIgnoreCase(err_name, &.{"CompleteErrorUnavailable"})) {
            return .{ .runtime_error = RuntimeServerError.ProviderStreamFailed, .retryable = true };
        }

        if (containsAnyIgnoreCase(message, &.{ "invalid json", "malformed json", "json parse", "decode error", "invalid response format", "invalid sse" }) or
            containsAnyIgnoreCase(err_name, &.{ "InvalidResponse", "InvalidJson", "InvalidCharacter", "UnexpectedToken", "Malformed", "ParseError", "DecodeError", "Unicode", "NotUtf8" }))
        {
            return .{ .runtime_error = RuntimeServerError.ProviderStreamFailed, .retryable = false };
        }

        return .{ .runtime_error = RuntimeServerError.ProviderStreamFailed, .retryable = false };
    }

    fn findProviderStreamMessage(events: []const ziggy_piai.types.AssistantMessageEvent) ?[]const u8 {
        for (events) |event| {
            switch (event) {
                .err => |message| return message,
                .done => |done| {
                    if (done.stop_reason == .err and done.error_message != null) return done.error_message.?;
                },
                else => {},
            }
        }
        return null;
    }

    fn resetProviderEvents(allocator: std.mem.Allocator, events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent)) void {
        deinitAssistantEvents(allocator, events);
        events.items.len = 0;
    }

    fn computeProviderRetryDelayMs(request_id: []const u8, attempt_idx: usize, retry_after_ms: ?u64) u64 {
        if (retry_after_ms) |value| return @min(value, PROVIDER_RETRY_MAX_DELAY_MS);

        const shift: u6 = @intCast(@min(attempt_idx, @as(usize, 10)));
        const exp_factor: u64 = @as(u64, 1) << shift;
        const exp_delay = std.math.mul(u64, PROVIDER_RETRY_BASE_DELAY_MS, exp_factor) catch PROVIDER_RETRY_MAX_DELAY_MS;
        const capped_delay = @min(exp_delay, PROVIDER_RETRY_MAX_DELAY_MS);

        if (PROVIDER_RETRY_JITTER_MS == 0) return capped_delay;

        var attempt_u64: u64 = @intCast(attempt_idx);
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(request_id);
        hasher.update(std.mem.asBytes(&attempt_u64));
        const hash = hasher.final();
        const jitter: u64 = hash % (PROVIDER_RETRY_JITTER_MS + 1);
        return @min(capped_delay + jitter, PROVIDER_RETRY_MAX_DELAY_MS);
    }

    fn waitProviderRetryBackoff(self: *RuntimeServer, job: *RuntimeQueueJob, run_id: ?[]const u8, delay_ms: u64) bool {
        if (delay_ms == 0) return self.isExecutionCancelled(job, run_id);

        // Release runtime lock while idling to avoid stalling unrelated queued jobs.
        self.runtime_mutex.unlock();
        defer self.runtime_mutex.lock();

        var remaining_ms = delay_ms;
        while (remaining_ms > 0) {
            const slice_ms: u64 = @min(remaining_ms, 100);
            std.Thread.sleep(slice_ms * std.time.ns_per_ms);
            if (self.isExecutionCancelled(job, run_id)) return true;
            remaining_ms -= slice_ms;
        }
        return self.isExecutionCancelled(job, run_id);
    }

    fn modelEquals(a: ziggy_piai.types.Model, b: ziggy_piai.types.Model) bool {
        return std.mem.eql(u8, a.provider, b.provider) and std.mem.eql(u8, a.id, b.id);
    }

    fn selectFallbackModelWithApiKey(
        self: *RuntimeServer,
        provider_runtime: *const ProviderRuntime,
        current_model: ziggy_piai.types.Model,
    ) !?ziggy_piai.types.Model {
        if (selectModel(provider_runtime, provider_runtime.default_provider_name, provider_runtime.default_model_name)) |default_model| {
            if (!modelEquals(default_model, current_model)) {
                if (self.resolveApiKey(provider_runtime, default_model.provider)) |key| {
                    self.allocator.free(key);
                    return default_model;
                } else |_| {}
            }
        }

        for (provider_runtime.model_registry.models.items) |candidate| {
            if (!std.mem.eql(u8, candidate.provider, current_model.provider)) continue;
            if (std.mem.eql(u8, candidate.id, current_model.id)) continue;
            if (self.resolveApiKey(provider_runtime, candidate.provider)) |key| {
                self.allocator.free(key);
                return candidate;
            } else |_| {}
        }

        return null;
    }

    fn completeWithProvider(
        self: *RuntimeServer,
        job: *RuntimeQueueJob,
        brain_name: []const u8,
        run_id: ?[]const u8,
    ) !ProviderCompletion {
        const provider_runtime = &(self.provider_runtime orelse return RuntimeServerError.ProviderModelNotFound);
        var debug_frames = std.ArrayListUnmanaged([]u8){};
        errdefer {
            for (debug_frames.items) |payload| self.allocator.free(payload);
            debug_frames.deinit(self.allocator);
        }

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

        const primary_model = selectModel(provider_runtime, provider_name, model_name) orelse return RuntimeServerError.ProviderModelNotFound;

        const brain_tool_specs = try buildProviderBrainTools(self.allocator);
        defer tool_registry.deinitProviderTools(self.allocator, brain_tool_specs);
        const world_tool_specs = try self.runtime.world_tools.exportProviderWorldTools(self.allocator);
        defer tool_registry.deinitProviderTools(self.allocator, world_tool_specs);

        const total_tool_count = brain_tool_specs.len + world_tool_specs.len;
        const provider_tools = try self.allocator.alloc(ziggy_piai.types.Tool, total_tool_count);
        defer self.allocator.free(provider_tools);
        const provider_tool_name_map = try self.allocator.alloc(ProviderToolNameMapEntry, total_tool_count);
        var provider_tool_name_count: usize = 0;
        defer {
            for (provider_tool_name_map[0..provider_tool_name_count]) |entry| self.allocator.free(entry.provider_name);
            self.allocator.free(provider_tool_name_map);
        }

        var provider_idx: usize = 0;
        for (brain_tool_specs) |spec| {
            const provider_tool_name = try providerToolNameFromRuntime(
                self.allocator,
                spec.name,
                provider_tool_name_map[0..provider_idx],
            );
            provider_tool_name_map[provider_idx] = .{
                .provider_name = provider_tool_name,
                .runtime_name = spec.name,
            };
            provider_tool_name_count += 1;
            provider_tools[provider_idx] = .{
                .name = provider_tool_name,
                .description = spec.description,
                .parameters_json = spec.parameters_json,
            };
            provider_idx += 1;
        }

        for (world_tool_specs) |spec| {
            const provider_tool_name = try providerToolNameFromRuntime(
                self.allocator,
                spec.name,
                provider_tool_name_map[0..provider_idx],
            );
            provider_tool_name_map[provider_idx] = .{
                .provider_name = provider_tool_name,
                .runtime_name = spec.name,
            };
            provider_tool_name_count += 1;
            provider_tools[provider_idx] = .{
                .name = provider_tool_name,
                .description = spec.description,
                .parameters_json = spec.parameters_json,
            };
            provider_idx += 1;
        }

        const tool_context_token_estimate = if (USE_EXPLICIT_JSON_TOOL_CALLS)
            0
        else
            estimateProviderToolContextTokens(provider_tools);

        var round: usize = 0;
        var total_calls: usize = 0;
        var followup_requested = false;
        var followup_rounds: usize = 0;
        var pending_tool_failure_followup = false;
        while (round < MAX_PROVIDER_TOOL_ROUNDS) : (round += 1) {
            if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;
            self.runtime.refreshCorePrompt(brain_name) catch |err| {
                std.log.warn("Failed to refresh core prompt memories for {s}: {s}", .{ brain_name, @errorName(err) });
            };

            const base_active_memory_prompt = try self.buildProviderActiveMemoryPrompt(brain_name);
            defer self.allocator.free(base_active_memory_prompt);
            const include_followup_hint = followup_requested;
            followup_requested = false;
            const active_memory_prompt = if (include_followup_hint)
                try std.fmt.allocPrint(
                    self.allocator,
                    "{s}\n\n<loop_hint>\nPrevious output requested followup_needed.\nContinue reasoning and emit exactly one of: tool_calls, wait_for marker, or task_complete marker.\nDo not emit narrative status text without one of those markers; plain text without a marker is protocol-invalid and will be ignored.\n</loop_hint>",
                    .{base_active_memory_prompt},
                )
            else
                try self.allocator.dupe(u8, base_active_memory_prompt);
            defer self.allocator.free(active_memory_prompt);

            var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(self.allocator);
            defer {
                deinitAssistantEvents(self.allocator, &events);
                events.deinit();
            }

            var selected_model = primary_model;
            var used_fallback = false;
            var attempt_idx: usize = 0;
            provider_attempt_loop: while (true) {
                if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;
                const provider_instructions = try self.buildProviderInstructions(
                    brain_name,
                    active_memory_prompt,
                    selected_model.context_window,
                    tool_context_token_estimate,
                );
                defer self.allocator.free(provider_instructions);
                const provider_instructions_safe = try self.normalizeProviderUtf8(provider_instructions);
                defer self.allocator.free(provider_instructions_safe);

                const active_memory_prompt_safe = try self.normalizeProviderUtf8(active_memory_prompt);
                defer self.allocator.free(active_memory_prompt_safe);
                const task_goal_for_turn = try self.loadMemoryTextByNameOrDefault(
                    brain_name,
                    memory_schema.GOAL_ACTIVE_MEM_NAME,
                    "No explicit active goal set.",
                );
                defer self.allocator.free(task_goal_for_turn);
                const task_goal_for_turn_safe = try self.normalizeProviderUtf8(task_goal_for_turn);
                defer self.allocator.free(task_goal_for_turn_safe);
                const provider_turn_input = try std.fmt.allocPrint(
                    self.allocator,
                    \\Current user request (Task Goal):
                    \\{s}
                    \\
                    \\<runtime_state source="internal">
                    \\{s}
                    \\</runtime_state>
                    \\
                    \\The runtime_state block above is internal system context generated by the runtime.
                    \\It is NOT a user-uploaded snapshot.
                    \\Do not claim the user sent this state.
                ,
                    .{ task_goal_for_turn_safe, active_memory_prompt_safe },
                );
                defer self.allocator.free(provider_turn_input);
                const messages = [_]ziggy_piai.types.Message{
                    .{
                        .role = .user,
                        .content = provider_turn_input,
                    },
                };

                const no_tools = [_]ziggy_piai.types.Tool{};
                const context = ziggy_piai.types.Context{
                    .system_prompt = provider_instructions_safe,
                    .messages = &messages,
                    .tools = if (USE_EXPLICIT_JSON_TOOL_CALLS) no_tools[0..] else provider_tools,
                };

                const api_key = try self.resolveApiKey(provider_runtime, selected_model.provider);
                defer self.allocator.free(api_key);

                self.logProviderRequestDebug(brain_name, selected_model, context, .{
                    .api_key = api_key,
                    .reasoning = think_level,
                });
                if (job.emit_debug) {
                    const request_payload_json = try self.buildProviderRequestDebugPayload(
                        brain_name,
                        selected_model,
                        context,
                        .{
                            .api_key = api_key,
                            .reasoning = think_level,
                        },
                        round,
                    );
                    defer self.allocator.free(request_payload_json);
                    try self.appendDebugFrame(
                        &debug_frames,
                        job.request_id,
                        "provider.request",
                        request_payload_json,
                    );
                }

                streamByModelFn(
                    self.allocator,
                    &provider_runtime.http_client,
                    &provider_runtime.api_registry,
                    selected_model,
                    context,
                    .{
                        .api_key = api_key,
                        .reasoning = think_level,
                    },
                    &events,
                ) catch |stream_err| {
                    const stream_error_name = @errorName(stream_err);
                    const failure = classifyProviderFailure(stream_error_name, null);
                    if (failure.retryable and attempt_idx + 1 < PROVIDER_STREAM_MAX_ATTEMPTS) {
                        const delay_ms = computeProviderRetryDelayMs(job.request_id, attempt_idx, failure.retry_after_ms);
                        if (job.emit_debug) {
                            const escaped_provider = try protocol.jsonEscape(self.allocator, selected_model.provider);
                            defer self.allocator.free(escaped_provider);
                            const escaped_model = try protocol.jsonEscape(self.allocator, selected_model.id);
                            defer self.allocator.free(escaped_model);
                            const escaped_error = try protocol.jsonEscape(self.allocator, stream_error_name);
                            defer self.allocator.free(escaped_error);
                            const retry_payload_json = try std.fmt.allocPrint(
                                self.allocator,
                                "{{\"provider\":\"{s}\",\"model\":\"{s}\",\"attempt\":{d},\"delay_ms\":{d},\"error\":\"{s}\"}}",
                                .{ escaped_provider, escaped_model, attempt_idx + 1, delay_ms, escaped_error },
                            );
                            defer self.allocator.free(retry_payload_json);
                            try self.appendDebugFrame(&debug_frames, job.request_id, "provider.retry", retry_payload_json);
                        }
                        resetProviderEvents(self.allocator, &events);
                        if (self.waitProviderRetryBackoff(job, run_id, delay_ms)) return RuntimeServerError.RuntimeJobCancelled;
                        attempt_idx += 1;
                        continue :provider_attempt_loop;
                    }

                    if (failure.retryable and !used_fallback) {
                        if (try self.selectFallbackModelWithApiKey(provider_runtime, selected_model)) |fallback_model| {
                            if (job.emit_debug) {
                                const escaped_from_provider = try protocol.jsonEscape(self.allocator, selected_model.provider);
                                defer self.allocator.free(escaped_from_provider);
                                const escaped_from_model = try protocol.jsonEscape(self.allocator, selected_model.id);
                                defer self.allocator.free(escaped_from_model);
                                const escaped_to_provider = try protocol.jsonEscape(self.allocator, fallback_model.provider);
                                defer self.allocator.free(escaped_to_provider);
                                const escaped_to_model = try protocol.jsonEscape(self.allocator, fallback_model.id);
                                defer self.allocator.free(escaped_to_model);
                                const escaped_error = try protocol.jsonEscape(self.allocator, stream_error_name);
                                defer self.allocator.free(escaped_error);
                                const fallback_payload_json = try std.fmt.allocPrint(
                                    self.allocator,
                                    "{{\"from_provider\":\"{s}\",\"from_model\":\"{s}\",\"to_provider\":\"{s}\",\"to_model\":\"{s}\",\"error\":\"{s}\"}}",
                                    .{ escaped_from_provider, escaped_from_model, escaped_to_provider, escaped_to_model, escaped_error },
                                );
                                defer self.allocator.free(fallback_payload_json);
                                try self.appendDebugFrame(&debug_frames, job.request_id, "provider.fallback", fallback_payload_json);
                            }
                            resetProviderEvents(self.allocator, &events);
                            selected_model = fallback_model;
                            used_fallback = true;
                            attempt_idx = 0;
                            continue :provider_attempt_loop;
                        }
                    }

                    if (job.emit_debug) {
                        const error_payload_json = try self.buildProviderErrorDebugPayload(
                            selected_model,
                            stream_error_name,
                            failure.runtime_error,
                            failure.retryable,
                            "stream_error",
                        );
                        defer self.allocator.free(error_payload_json);
                        try self.setProviderErrorDebugPayload(job, error_payload_json);
                        try self.appendDebugFrame(&debug_frames, job.request_id, "provider.error", error_payload_json);
                    } else {
                        const error_payload_json = try self.buildProviderErrorDebugPayload(
                            selected_model,
                            stream_error_name,
                            failure.runtime_error,
                            failure.retryable,
                            "stream_error",
                        );
                        defer self.allocator.free(error_payload_json);
                        try self.setProviderErrorDebugPayload(job, error_payload_json);
                    }

                    return failure.runtime_error;
                };

                if (self.isExecutionCancelled(job, run_id)) return RuntimeServerError.RuntimeJobCancelled;

                if (findProviderStreamMessage(events.items)) |provider_error_message| {
                    const failure = classifyProviderFailure(null, provider_error_message);
                    if (failure.retryable and attempt_idx + 1 < PROVIDER_STREAM_MAX_ATTEMPTS) {
                        const delay_ms = computeProviderRetryDelayMs(job.request_id, attempt_idx, failure.retry_after_ms);
                        if (job.emit_debug) {
                            const escaped_provider = try protocol.jsonEscape(self.allocator, selected_model.provider);
                            defer self.allocator.free(escaped_provider);
                            const escaped_model = try protocol.jsonEscape(self.allocator, selected_model.id);
                            defer self.allocator.free(escaped_model);
                            const escaped_error = try protocol.jsonEscape(self.allocator, provider_error_message);
                            defer self.allocator.free(escaped_error);
                            const retry_payload_json = try std.fmt.allocPrint(
                                self.allocator,
                                "{{\"provider\":\"{s}\",\"model\":\"{s}\",\"attempt\":{d},\"delay_ms\":{d},\"error\":\"{s}\"}}",
                                .{ escaped_provider, escaped_model, attempt_idx + 1, delay_ms, escaped_error },
                            );
                            defer self.allocator.free(retry_payload_json);
                            try self.appendDebugFrame(&debug_frames, job.request_id, "provider.retry", retry_payload_json);
                        }
                        resetProviderEvents(self.allocator, &events);
                        if (self.waitProviderRetryBackoff(job, run_id, delay_ms)) return RuntimeServerError.RuntimeJobCancelled;
                        attempt_idx += 1;
                        continue :provider_attempt_loop;
                    }

                    if (failure.retryable and !used_fallback) {
                        if (try self.selectFallbackModelWithApiKey(provider_runtime, selected_model)) |fallback_model| {
                            if (job.emit_debug) {
                                const escaped_from_provider = try protocol.jsonEscape(self.allocator, selected_model.provider);
                                defer self.allocator.free(escaped_from_provider);
                                const escaped_from_model = try protocol.jsonEscape(self.allocator, selected_model.id);
                                defer self.allocator.free(escaped_from_model);
                                const escaped_to_provider = try protocol.jsonEscape(self.allocator, fallback_model.provider);
                                defer self.allocator.free(escaped_to_provider);
                                const escaped_to_model = try protocol.jsonEscape(self.allocator, fallback_model.id);
                                defer self.allocator.free(escaped_to_model);
                                const escaped_error = try protocol.jsonEscape(self.allocator, provider_error_message);
                                defer self.allocator.free(escaped_error);
                                const fallback_payload_json = try std.fmt.allocPrint(
                                    self.allocator,
                                    "{{\"from_provider\":\"{s}\",\"from_model\":\"{s}\",\"to_provider\":\"{s}\",\"to_model\":\"{s}\",\"error\":\"{s}\"}}",
                                    .{ escaped_from_provider, escaped_from_model, escaped_to_provider, escaped_to_model, escaped_error },
                                );
                                defer self.allocator.free(fallback_payload_json);
                                try self.appendDebugFrame(&debug_frames, job.request_id, "provider.fallback", fallback_payload_json);
                            }
                            resetProviderEvents(self.allocator, &events);
                            selected_model = fallback_model;
                            used_fallback = true;
                            attempt_idx = 0;
                            continue :provider_attempt_loop;
                        }
                    }

                    if (job.emit_debug) {
                        const error_payload_json = try self.buildProviderErrorDebugPayload(
                            selected_model,
                            provider_error_message,
                            failure.runtime_error,
                            failure.retryable,
                            "provider_event",
                        );
                        defer self.allocator.free(error_payload_json);
                        try self.setProviderErrorDebugPayload(job, error_payload_json);
                        try self.appendDebugFrame(&debug_frames, job.request_id, "provider.error", error_payload_json);
                    } else {
                        const error_payload_json = try self.buildProviderErrorDebugPayload(
                            selected_model,
                            provider_error_message,
                            failure.runtime_error,
                            failure.retryable,
                            "provider_event",
                        );
                        defer self.allocator.free(error_payload_json);
                        try self.setProviderErrorDebugPayload(job, error_payload_json);
                    }

                    return failure.runtime_error;
                }

                break;
            }

            var assistant = try extractAssistantMessage(self.allocator, events.items);
            errdefer deinitOwnedAssistantMessage(self.allocator, &assistant);
            if (job.emit_debug) {
                const response_payload_json = try self.buildProviderResponseDebugPayload(assistant, round);
                defer self.allocator.free(response_payload_json);
                try self.appendDebugFrame(
                    &debug_frames,
                    job.request_id,
                    "provider.response",
                    response_payload_json,
                );
            }

            const tool_calls = assistant.tool_calls;
            if (tool_calls.len == 0) {
                const structured_tool_calls = try self.parseStructuredToolCalls(assistant.text, round);
                defer {
                    for (structured_tool_calls) |*call| call.deinit(self.allocator);
                    if (structured_tool_calls.len > 0) self.allocator.free(structured_tool_calls);
                }
                if (structured_tool_calls.len > 0) {
                    if (structured_tool_calls.len > 1) {
                        if (job.emit_debug) {
                            const payload = try std.fmt.allocPrint(
                                self.allocator,
                                "{{\"round\":{d},\"reason\":\"multiple_tool_calls_not_allowed\",\"incoming_calls\":{d}}}",
                                .{ round, structured_tool_calls.len },
                            );
                            defer self.allocator.free(payload);
                            try self.appendDebugFrame(&debug_frames, job.request_id, "provider.tool_call_rejected", payload);
                        }

                        try self.appendAssistantStructuredToolCallMessage(brain_name, assistant.text, structured_tool_calls);
                        try self.appendToolProtocolErrorResult(
                            brain_name,
                            "invalid_tool_batch",
                            "Emit exactly one tool call per act step. Do not batch tool calls.",
                            structured_tool_calls.len,
                        );
                        pending_tool_failure_followup = true;
                        followup_rounds += 1;
                        if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                            deinitOwnedAssistantMessage(self.allocator, &assistant);
                            return RuntimeServerError.ProviderToolLoopExceeded;
                        }
                        followup_requested = true;
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        continue;
                    }

                    if (total_calls + structured_tool_calls.len > MAX_PROVIDER_TOOL_CALLS_PER_TURN) {
                        if (job.emit_debug) {
                            const payload = try std.fmt.allocPrint(
                                self.allocator,
                                "{{\"reason\":\"tool_call_cap\",\"round\":{d},\"total_calls\":{d},\"incoming_calls\":{d},\"cap\":{d}}}",
                                .{ round, total_calls, structured_tool_calls.len, MAX_PROVIDER_TOOL_CALLS_PER_TURN },
                            );
                            defer self.allocator.free(payload);
                            try self.appendDebugFrame(&debug_frames, job.request_id, "provider.loop_exit", payload);
                        }
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return self.finalizeProviderCompletion(&debug_frames, "", true, false);
                    }
                    total_calls += structured_tool_calls.len;
                    try self.appendAssistantStructuredToolCallMessage(brain_name, assistant.text, structured_tool_calls);

                    for (structured_tool_calls) |tool_call| {
                        const runtime_tool_name = resolveRuntimeToolName(tool_call.name, provider_tool_name_map);
                        const args_with_call_id = try injectToolCallId(self.allocator, tool_call.arguments_json, tool_call.id);
                        defer self.allocator.free(args_with_call_id);
                        if (job.emit_debug) {
                            const tool_call_payload_json = try self.buildProviderStructuredToolCallDebugPayload(
                                tool_call,
                                runtime_tool_name,
                                args_with_call_id,
                                round,
                            );
                            defer self.allocator.free(tool_call_payload_json);
                            try self.appendDebugFrame(
                                &debug_frames,
                                job.request_id,
                                "provider.tool_call",
                                tool_call_payload_json,
                            );
                        }
                        try self.runtime.queueToolUse(brain_name, runtime_tool_name, args_with_call_id);
                    }

                    var structured_tool_payloads = std.ArrayListUnmanaged([]u8){};
                    defer {
                        for (structured_tool_payloads.items) |payload| self.allocator.free(payload);
                        structured_tool_payloads.deinit(self.allocator);
                    }

                    self.runPendingTicks(job, run_id, &structured_tool_payloads) catch |err| {
                        if (err == RuntimeServerError.RuntimeJobCancelled) return err;
                        return err;
                    };
                    if (job.emit_debug) {
                        try self.appendToolResultDebugFrames(
                            &debug_frames,
                            job.request_id,
                            round,
                            structured_tool_payloads.items,
                        );
                    }
                    pending_tool_failure_followup = self.toolPayloadBatchHasError(structured_tool_payloads.items);
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    continue;
                }

                var directive = try self.parseProviderLoopDirective(assistant.text);
                defer directive.deinit(self.allocator);

                const implicit_wait_fallback =
                    directive.action == .wait_for_user and
                    directive.message == null and
                    isImplicitWaitFallbackReason(directive.reason);

                if (implicit_wait_fallback and total_calls == 0 and !pending_tool_failure_followup) {
                    const fallback_text = std.mem.trim(u8, assistant.text, " \t\r\n");
                    if (fallback_text.len > 0) {
                        if (isImplicitActionIntentText(fallback_text)) {
                            followup_rounds += 1;
                            if (job.emit_debug) {
                                const escaped_reason = try protocol.jsonEscape(self.allocator, directive.reason);
                                defer self.allocator.free(escaped_reason);
                                const payload = try std.fmt.allocPrint(
                                    self.allocator,
                                    "{{\"round\":{d},\"reason\":\"pre_tool_implicit_wait_action_intent\",\"directive_reason\":\"{s}\",\"followup_rounds\":{d},\"total_calls\":{d}}}",
                                    .{ round, escaped_reason, followup_rounds, total_calls },
                                );
                                defer self.allocator.free(payload);
                                try self.appendDebugFrame(&debug_frames, job.request_id, "provider.followup", payload);
                            }

                            if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                                const completion = try self.finalizeProviderCompletion(&debug_frames, fallback_text, false, false);
                                deinitOwnedAssistantMessage(self.allocator, &assistant);
                                return completion;
                            }

                            followup_requested = true;
                            deinitOwnedAssistantMessage(self.allocator, &assistant);
                            continue;
                        }

                        const completion = try self.finalizeProviderCompletion(&debug_frames, fallback_text, false, false);
                        pending_tool_failure_followup = false;
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return completion;
                    }
                }

                if (implicit_wait_fallback and total_calls > 0) {
                    const fallback_text = std.mem.trim(u8, assistant.text, " \t\r\n");
                    if (fallback_text.len > 0 and !isLowSignalFollowupText(fallback_text)) {
                        const completion = try self.finalizeProviderCompletion(&debug_frames, fallback_text, false, false);
                        pending_tool_failure_followup = false;
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return completion;
                    }

                    followup_rounds += 1;
                    if (job.emit_debug) {
                        const escaped_reason = try protocol.jsonEscape(self.allocator, directive.reason);
                        defer self.allocator.free(escaped_reason);
                        const payload = try std.fmt.allocPrint(
                            self.allocator,
                            "{{\"round\":{d},\"reason\":\"post_tool_implicit_wait\",\"directive_reason\":\"{s}\",\"followup_rounds\":{d},\"total_calls\":{d}}}",
                            .{ round, escaped_reason, followup_rounds, total_calls },
                        );
                        defer self.allocator.free(payload);
                        try self.appendDebugFrame(&debug_frames, job.request_id, "provider.followup", payload);
                    }

                    if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                        const exhausted_text = std.mem.trim(u8, assistant.text, " \t\r\n");
                        if (exhausted_text.len > 0) {
                            const completion = try self.finalizeProviderCompletion(&debug_frames, exhausted_text, false, false);
                            deinitOwnedAssistantMessage(self.allocator, &assistant);
                            return completion;
                        }
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return RuntimeServerError.ProviderToolLoopExceeded;
                    }

                    followup_requested = true;
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    continue;
                }

                if (pending_tool_failure_followup and directive.action == .wait_for_user) {
                    followup_rounds += 1;
                    if (job.emit_debug) {
                        const escaped_reason = try protocol.jsonEscape(self.allocator, directive.reason);
                        defer self.allocator.free(escaped_reason);
                        const payload = try std.fmt.allocPrint(
                            self.allocator,
                            "{{\"round\":{d},\"reason\":\"post_tool_error_wait_blocked\",\"directive_reason\":\"{s}\",\"followup_rounds\":{d},\"total_calls\":{d}}}",
                            .{ round, escaped_reason, followup_rounds, total_calls },
                        );
                        defer self.allocator.free(payload);
                        try self.appendDebugFrame(&debug_frames, job.request_id, "provider.followup", payload);
                    }

                    if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                        const exhausted_text = std.mem.trim(u8, assistant.text, " \t\r\n");
                        if (exhausted_text.len > 0) {
                            const completion = try self.finalizeProviderCompletion(&debug_frames, exhausted_text, false, false);
                            deinitOwnedAssistantMessage(self.allocator, &assistant);
                            return completion;
                        }
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return RuntimeServerError.ProviderToolLoopExceeded;
                    }

                    followup_requested = true;
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    continue;
                }

                if (directive.action == .followup_needed) {
                    followup_rounds += 1;
                    if (job.emit_debug) {
                        const escaped_reason = try protocol.jsonEscape(self.allocator, directive.reason);
                        defer self.allocator.free(escaped_reason);
                        const payload = try std.fmt.allocPrint(
                            self.allocator,
                            "{{\"round\":{d},\"reason\":\"{s}\",\"followup_rounds\":{d}}}",
                            .{ round, escaped_reason, followup_rounds },
                        );
                        defer self.allocator.free(payload);
                        try self.appendDebugFrame(&debug_frames, job.request_id, "provider.followup", payload);
                    }

                    if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                        const exhausted_text = std.mem.trim(u8, assistant.text, " \t\r\n");
                        if (exhausted_text.len > 0) {
                            const completion = try self.finalizeProviderCompletion(&debug_frames, exhausted_text, false, false);
                            deinitOwnedAssistantMessage(self.allocator, &assistant);
                            return completion;
                        }
                        deinitOwnedAssistantMessage(self.allocator, &assistant);
                        return RuntimeServerError.ProviderToolLoopExceeded;
                    }

                    followup_requested = true;
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    continue;
                }

                if (directive.action == .task_complete) {
                    const completion_text = directive.message orelse assistant.text;
                    const completion = try self.finalizeProviderCompletion(&debug_frames, completion_text, false, true);
                    pending_tool_failure_followup = false;
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    return completion;
                }

                if (directive.action == .wait_for_user) {
                    const wait_text = if (directive.message) |message|
                        message
                    else
                        std.mem.trim(u8, assistant.text, " \t\r\n");
                    const completion = try self.finalizeProviderCompletion(&debug_frames, wait_text, true, false);
                    pending_tool_failure_followup = false;
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    return completion;
                }

                pending_tool_failure_followup = false;
                deinitOwnedAssistantMessage(self.allocator, &assistant);
                return self.finalizeProviderCompletion(&debug_frames, "", true, false);
            }

            if (tool_calls.len > 1) {
                if (job.emit_debug) {
                    const payload = try std.fmt.allocPrint(
                        self.allocator,
                        "{{\"round\":{d},\"reason\":\"multiple_tool_calls_not_allowed\",\"incoming_calls\":{d}}}",
                        .{ round, tool_calls.len },
                    );
                    defer self.allocator.free(payload);
                    try self.appendDebugFrame(&debug_frames, job.request_id, "provider.tool_call_rejected", payload);
                }

                try self.appendAssistantToolCallMessage(brain_name, assistant.text, tool_calls);
                try self.appendToolProtocolErrorResult(
                    brain_name,
                    "invalid_tool_batch",
                    "Emit exactly one tool call per act step. Do not batch tool calls.",
                    tool_calls.len,
                );
                pending_tool_failure_followup = true;
                followup_rounds += 1;
                if (followup_rounds > MAX_PROVIDER_FOLLOWUP_ROUNDS) {
                    deinitOwnedAssistantMessage(self.allocator, &assistant);
                    return RuntimeServerError.ProviderToolLoopExceeded;
                }
                followup_requested = true;
                deinitOwnedAssistantMessage(self.allocator, &assistant);
                continue;
            }

            if (total_calls + tool_calls.len > MAX_PROVIDER_TOOL_CALLS_PER_TURN) {
                if (job.emit_debug) {
                    const payload = try std.fmt.allocPrint(
                        self.allocator,
                        "{{\"reason\":\"tool_call_cap\",\"round\":{d},\"total_calls\":{d},\"incoming_calls\":{d},\"cap\":{d}}}",
                        .{ round, total_calls, tool_calls.len, MAX_PROVIDER_TOOL_CALLS_PER_TURN },
                    );
                    defer self.allocator.free(payload);
                    try self.appendDebugFrame(&debug_frames, job.request_id, "provider.loop_exit", payload);
                }
                deinitOwnedAssistantMessage(self.allocator, &assistant);
                return self.finalizeProviderCompletion(&debug_frames, "", true, false);
            }
            total_calls += tool_calls.len;

            try self.appendAssistantToolCallMessage(brain_name, assistant.text, tool_calls);

            for (tool_calls) |tool_call| {
                const runtime_tool_name = resolveRuntimeToolName(tool_call.name, provider_tool_name_map);
                const args_with_call_id = try injectToolCallId(self.allocator, tool_call.arguments_json, tool_call.id);
                defer self.allocator.free(args_with_call_id);
                if (job.emit_debug) {
                    const tool_call_payload_json = try self.buildProviderToolCallDebugPayload(
                        tool_call,
                        runtime_tool_name,
                        args_with_call_id,
                        round,
                    );
                    defer self.allocator.free(tool_call_payload_json);
                    try self.appendDebugFrame(
                        &debug_frames,
                        job.request_id,
                        "provider.tool_call",
                        tool_call_payload_json,
                    );
                }
                try self.runtime.queueToolUse(brain_name, runtime_tool_name, args_with_call_id);
            }

            var tool_payloads = std.ArrayListUnmanaged([]u8){};
            defer {
                for (tool_payloads.items) |payload| self.allocator.free(payload);
                tool_payloads.deinit(self.allocator);
            }

            self.runPendingTicks(job, run_id, &tool_payloads) catch |err| {
                if (err == RuntimeServerError.RuntimeJobCancelled) return err;
                return err;
            };
            if (job.emit_debug) {
                try self.appendToolResultDebugFrames(
                    &debug_frames,
                    job.request_id,
                    round,
                    tool_payloads.items,
                );
            }
            pending_tool_failure_followup = self.toolPayloadBatchHasError(tool_payloads.items);
            deinitOwnedAssistantMessage(self.allocator, &assistant);
        }

        if (job.emit_debug) {
            const payload = try std.fmt.allocPrint(
                self.allocator,
                "{{\"reason\":\"round_cap\",\"rounds\":{d},\"max_rounds\":{d}}}",
                .{ round, MAX_PROVIDER_TOOL_ROUNDS },
            );
            defer self.allocator.free(payload);
            try self.appendDebugFrame(&debug_frames, job.request_id, "provider.loop_exit", payload);
        }
        return self.finalizeProviderCompletion(&debug_frames, "", true, false);
    }

    fn buildProviderInstructions(
        self: *RuntimeServer,
        brain_name: []const u8,
        active_memory_prompt: []const u8,
        context_window: u32,
        tool_context_token_estimate: usize,
    ) ![]u8 {
        const core_prompt = try self.buildCoreSystemPrompt(brain_name);
        defer self.allocator.free(core_prompt);

        const dynamic_board = try self.buildDynamicCoreInfoBoard(
            brain_name,
            core_prompt,
            active_memory_prompt,
            context_window,
            tool_context_token_estimate,
        );
        defer self.allocator.free(dynamic_board);
        const policy = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.POLICY_MEM_NAME, memory_schema.POLICY_TEXT);
        defer self.allocator.free(policy);
        const loop_contract = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.LOOP_CONTRACT_MEM_NAME, memory_schema.LOOP_CONTRACT_TEXT);
        defer self.allocator.free(loop_contract);
        const tool_contract = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.TOOL_CONTRACT_MEM_NAME, memory_schema.TOOL_CONTRACT_TEXT);
        defer self.allocator.free(tool_contract);
        const completion_contract = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.COMPLETION_CONTRACT_MEM_NAME, memory_schema.COMPLETION_CONTRACT_TEXT);
        defer self.allocator.free(completion_contract);
        const task_goal = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.GOAL_ACTIVE_MEM_NAME, "No explicit active goal set.");
        defer self.allocator.free(task_goal);
        const ltm_summary = try self.loadMemoryTextByNameOrDefault(brain_name, memory_schema.CONTEXT_SUMMARY_MEM_NAME, "No long-term summary yet.");
        defer self.allocator.free(ltm_summary);

        return prompt_compiler.compile(self.allocator, .{
            .core_prompt = core_prompt,
            .policy = policy,
            .loop_contract = loop_contract,
            .tool_contract = tool_contract,
            .completion_contract = completion_contract,
            .task_goal = task_goal,
            .dynamic_board = dynamic_board,
            .working_memory_snapshot = active_memory_prompt,
            .ltm_summary = ltm_summary,
        });
    }

    fn buildDynamicCoreInfoBoard(
        self: *RuntimeServer,
        brain_name: []const u8,
        core_prompt: []const u8,
        active_memory_prompt: []const u8,
        context_window: u32,
        tool_context_token_estimate: usize,
    ) ![]u8 {
        const context_limit = @as(usize, context_window);
        const unix_time = std.time.timestamp();
        const timestamp_utc = try formatUtcTimestamp(self.allocator, unix_time);
        defer self.allocator.free(timestamp_utc);

        // Two-pass estimate so the board includes itself in the approximation.
        const base_estimate = estimateTokenCount(core_prompt) + estimateTokenCount(active_memory_prompt) + tool_context_token_estimate;
        const preview_board = try std.fmt.allocPrint(
            self.allocator,
            \\## Dynamic Info Board
            \\- agent_name: {s}
            \\- brain_name: {s}
            \\- approximate_context_used: {d}/{d}
            \\- date_time_utc: {s}
            \\- unix_time: {d}
            \\
        ,
            .{ self.runtime.agent_id, brain_name, base_estimate, context_limit, timestamp_utc, unix_time },
        );
        defer self.allocator.free(preview_board);

        const final_estimate = estimateTokenCount(core_prompt) +
            estimateTokenCount(active_memory_prompt) +
            tool_context_token_estimate +
            estimateTokenCount(preview_board);

        return std.fmt.allocPrint(
            self.allocator,
            \\## Dynamic Info Board
            \\- agent_name: {s}
            \\- brain_name: {s}
            \\- approximate_context_used: {d}/{d}
            \\- date_time_utc: {s}
            \\- unix_time: {d}
            \\
        ,
            .{ self.runtime.agent_id, brain_name, final_estimate, context_limit, timestamp_utc, unix_time },
        );
    }

    fn normalizeProviderUtf8(self: *RuntimeServer, input: []const u8) ![]u8 {
        if (std.unicode.Utf8View.init(input)) |_| {
            return self.allocator.dupe(u8, input);
        } else |_| {}

        const replacement = "\xEF\xBF\xBD";
        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        var i: usize = 0;
        while (i < input.len) {
            const byte = input[i];
            if (byte < 0x80) {
                try out.append(self.allocator, byte);
                i += 1;
                continue;
            }

            const seq_len = std.unicode.utf8ByteSequenceLength(byte) catch {
                try out.appendSlice(self.allocator, replacement);
                i += 1;
                continue;
            };
            const needed: usize = @intCast(seq_len);
            if (i + needed > input.len) {
                try out.appendSlice(self.allocator, replacement);
                break;
            }

            const candidate = input[i .. i + needed];
            if (std.unicode.Utf8View.init(candidate)) |_| {
                try out.appendSlice(self.allocator, candidate);
                i += needed;
            } else |_| {
                try out.appendSlice(self.allocator, replacement);
                i += 1;
            }
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn estimateProviderToolContextTokens(tools: []const ziggy_piai.types.Tool) usize {
        var total_bytes: usize = 0;
        for (tools) |tool| {
            total_bytes += tool.name.len + tool.description.len + tool.parameters_json.len + 24;
        }
        return estimateTokenCountFromBytes(total_bytes);
    }

    fn estimateTokenCount(text: []const u8) usize {
        return estimateTokenCountFromBytes(text.len);
    }

    fn estimateTokenCountFromBytes(bytes: usize) usize {
        if (bytes == 0) return 0;
        return (bytes + 3) / 4;
    }

    fn formatUtcTimestamp(allocator: std.mem.Allocator, unix_time: i64) ![]u8 {
        const unix_seconds: u64 = if (unix_time < 0) 0 else @as(u64, @intCast(unix_time));
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = unix_seconds };
        const epoch_day = epoch_seconds.getEpochDay();
        const day_seconds = epoch_seconds.getDaySeconds();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        return std.fmt.allocPrint(
            allocator,
            "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC",
            .{
                year_day.year,
                month_day.month.numeric(),
                month_day.day_index + 1,
                day_seconds.getHoursIntoDay(),
                day_seconds.getMinutesIntoHour(),
                day_seconds.getSecondsIntoMinute(),
            },
        );
    }

    fn buildProviderBrainTools(allocator: std.mem.Allocator) ![]tool_registry.ProviderTool {
        var out = std.ArrayListUnmanaged(tool_registry.ProviderTool){};
        errdefer {
            for (out.items) |*tool| tool.deinit(allocator);
            out.deinit(allocator);
        }

        for (brain_tools.brain_tool_schemas) |schema| {
            const parameters_json = try buildBrainToolParametersJson(
                allocator,
                schema.required_fields,
                schema.optional_fields,
            );
            errdefer allocator.free(parameters_json);

            try out.append(allocator, .{
                .name = try allocator.dupe(u8, schema.name),
                .description = try allocator.dupe(u8, schema.description),
                .parameters_json = parameters_json,
            });
        }

        return out.toOwnedSlice(allocator);
    }

    fn buildBrainToolParametersJson(
        allocator: std.mem.Allocator,
        required_fields: []const []const u8,
        optional_fields: []const []const u8,
    ) ![]u8 {
        var out = std.ArrayListUnmanaged(u8){};
        defer out.deinit(allocator);

        try out.appendSlice(allocator, "{\"type\":\"object\",\"properties\":{");
        var has_property = false;
        for (required_fields, 0..) |field, idx| {
            _ = idx;
            if (has_property) try out.append(allocator, ',');
            try out.appendSlice(allocator, "\"");
            try appendJsonEscaped(allocator, &out, field);
            try out.appendSlice(allocator, "\":");
            try appendBrainToolFieldSchemaJson(allocator, &out, field);
            has_property = true;
        }
        for (optional_fields) |field| {
            if (containsField(required_fields, field)) continue;
            if (has_property) try out.append(allocator, ',');
            try out.appendSlice(allocator, "\"");
            try appendJsonEscaped(allocator, &out, field);
            try out.appendSlice(allocator, "\":");
            try appendBrainToolFieldSchemaJson(allocator, &out, field);
            has_property = true;
        }
        try out.appendSlice(allocator, "},\"required\":[");
        for (required_fields, 0..) |field, idx| {
            if (idx > 0) try out.append(allocator, ',');
            try out.appendSlice(allocator, "\"");
            try appendJsonEscaped(allocator, &out, field);
            try out.appendSlice(allocator, "\"");
        }
        try out.appendSlice(allocator, "]}");

        return out.toOwnedSlice(allocator);
    }

    fn containsField(fields: []const []const u8, candidate: []const u8) bool {
        for (fields) |field| {
            if (std.mem.eql(u8, field, candidate)) return true;
        }
        return false;
    }

    fn brainToolFieldType(field: []const u8) []const u8 {
        if (std.mem.eql(u8, field, "mem_id")) return "string";
        if (std.mem.eql(u8, field, "name")) return "string";
        if (std.mem.eql(u8, field, "kind")) return "string";
        if (std.mem.eql(u8, field, "query")) return "string";
        if (std.mem.eql(u8, field, "message")) return "string";
        if (std.mem.eql(u8, field, "target_brain")) return "string";
        if (std.mem.eql(u8, field, "version")) return "integer";
        if (std.mem.eql(u8, field, "limit")) return "integer";
        if (std.mem.eql(u8, field, "talk_id")) return "integer";
        if (std.mem.eql(u8, field, "content")) return "object";
        if (std.mem.eql(u8, field, "events")) return "array";
        if (std.mem.eql(u8, field, "write_protected")) return "boolean";
        if (std.mem.eql(u8, field, "unevictable")) return "boolean";
        return "string";
    }

    fn appendBrainToolFieldSchemaJson(
        allocator: std.mem.Allocator,
        out: *std.ArrayListUnmanaged(u8),
        field: []const u8,
    ) !void {
        if (std.mem.eql(u8, field, "content")) {
            // content accepts any JSON value in memory_create/memory_mutate.
            try out.appendSlice(allocator, "{}");
            return;
        }

        if (std.mem.eql(u8, field, "events")) {
            try out.appendSlice(allocator, "{\"type\":\"array\",\"items\":{\"type\":\"object\"}}");
            return;
        }

        try out.appendSlice(allocator, "{\"type\":\"");
        try out.appendSlice(allocator, brainToolFieldType(field));
        try out.appendSlice(allocator, "\"}");
    }

    fn appendJsonEscaped(
        allocator: std.mem.Allocator,
        out: *std.ArrayListUnmanaged(u8),
        raw: []const u8,
    ) !void {
        for (raw) |char| {
            switch (char) {
                '\\' => try out.appendSlice(allocator, "\\\\"),
                '"' => try out.appendSlice(allocator, "\\\""),
                '\n' => try out.appendSlice(allocator, "\\n"),
                '\r' => try out.appendSlice(allocator, "\\r"),
                '\t' => try out.appendSlice(allocator, "\\t"),
                else => try out.append(allocator, char),
            }
        }
    }

    fn buildCoreSystemPrompt(self: *RuntimeServer, brain_name: []const u8) ![]u8 {
        const snapshot = try self.runtime.active_memory.snapshotActive(self.allocator, brain_name);
        defer memory.deinitItems(self.allocator, snapshot);

        var out = std.ArrayListUnmanaged(u8){};
        errdefer out.deinit(self.allocator);

        // Always render the base core instructions first, as plain markdown.
        for (snapshot) |item| {
            if (!isCorePromptMemory(item)) continue;
            if (shouldExcludeCorePromptItem(item)) continue;
            if (!isBaseCorePromptMemory(item)) continue;
            try self.appendCorePromptEntry(&out, item, false);
        }

        for (snapshot) |item| {
            if (!isCorePromptMemory(item)) continue;
            if (shouldExcludeCorePromptItem(item)) continue;
            if (isBaseCorePromptMemory(item)) continue;
            try self.appendCorePromptEntry(&out, item, true);
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn appendCorePromptEntry(
        self: *RuntimeServer,
        out: *std.ArrayListUnmanaged(u8),
        item: memory.ActiveMemoryItem,
        include_mem_id: bool,
    ) !void {
        const text = decodeMemoryText(self.allocator, item.content_json) catch item.content_json;
        const owns_text = text.ptr != item.content_json.ptr;
        defer if (owns_text) self.allocator.free(text);

        if (include_mem_id) {
            try out.appendSlice(self.allocator, "[");
            try out.appendSlice(self.allocator, item.mem_id);
            try out.appendSlice(self.allocator, "] ");
        }

        try out.appendSlice(self.allocator, text);
        if (text.len == 0 or text[text.len - 1] != '\n') {
            try out.appendSlice(self.allocator, "\n");
        }
    }

    fn isCorePromptMemory(item: memory.ActiveMemoryItem) bool {
        return std.mem.eql(u8, item.kind, "core.system_prompt") or std.mem.eql(u8, item.kind, BASE_CORE_PROMPT_KIND);
    }

    fn isBaseCorePromptMemory(item: memory.ActiveMemoryItem) bool {
        if (std.mem.eql(u8, item.kind, BASE_CORE_PROMPT_KIND)) return true;
        const parsed = memid.MemId.parse(item.mem_id) catch return false;
        return std.mem.eql(u8, parsed.name, BASE_CORE_PROMPT_NAME);
    }

    fn shouldExcludeCorePromptItem(item: memory.ActiveMemoryItem) bool {
        const parsed = memid.MemId.parse(item.mem_id) catch return false;
        return std.mem.eql(u8, parsed.name, CORE_CAPABILITIES_PROMPT_NAME) or
            std.mem.eql(u8, parsed.name, CORE_IDENTITY_GUIDANCE_PROMPT_NAME);
    }

    fn loadMemoryTextByNameOrDefault(
        self: *RuntimeServer,
        brain_name: []const u8,
        name: []const u8,
        fallback: []const u8,
    ) ![]u8 {
        var item = (self.loadMemoryByName(brain_name, name) catch null) orelse return self.allocator.dupe(u8, fallback);
        defer item.deinit(self.allocator);
        return decodeMemoryText(self.allocator, item.content_json);
    }

    fn decodeMemoryText(allocator: std.mem.Allocator, content_json: []const u8) ![]u8 {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, content_json, .{}) catch {
            return allocator.dupe(u8, content_json);
        };
        defer parsed.deinit();

        if (parsed.value == .string) {
            return allocator.dupe(u8, parsed.value.string);
        }
        return allocator.dupe(u8, content_json);
    }

    fn resolveRuntimeToolName(provider_name: []const u8, mapping: []const ProviderToolNameMapEntry) []const u8 {
        for (mapping) |entry| {
            if (std.mem.eql(u8, entry.provider_name, provider_name)) return entry.runtime_name;
        }
        return provider_name;
    }

    fn providerToolNameFromRuntime(
        allocator: std.mem.Allocator,
        runtime_name: []const u8,
        existing: []const ProviderToolNameMapEntry,
    ) ![]u8 {
        if (!isProviderCompatibleToolName(runtime_name)) {
            std.log.warn("Invalid runtime tool name for provider schema: {s}", .{runtime_name});
            return RuntimeServerError.ProviderRequestInvalid;
        }

        if (toolNameExists(existing, runtime_name)) {
            std.log.warn("Duplicate provider tool name detected: {s}", .{runtime_name});
            return RuntimeServerError.ProviderRequestInvalid;
        }

        return allocator.dupe(u8, runtime_name);
    }

    fn isProviderCompatibleToolName(name: []const u8) bool {
        if (name.len == 0) return false;
        for (name) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return false;
        }
        return true;
    }

    fn toolNameExists(existing: []const ProviderToolNameMapEntry, candidate: []const u8) bool {
        for (existing) |entry| {
            if (std.mem.eql(u8, entry.provider_name, candidate)) return true;
        }
        return false;
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

        var non_core_snapshot = std.ArrayListUnmanaged(memory.ActiveMemoryItem){};
        defer non_core_snapshot.deinit(self.allocator);
        for (snapshot) |item| {
            if (!shouldIncludeProviderActiveMemoryItem(item)) continue;
            try non_core_snapshot.append(self.allocator, item);
        }

        const state_json = try memory.toActiveMemoryJson(self.allocator, brain_name, non_core_snapshot.items);
        defer self.allocator.free(state_json);
        return self.allocator.dupe(u8, state_json);
    }

    fn shouldIncludeProviderActiveMemoryItem(item: memory.ActiveMemoryItem) bool {
        if (isCorePromptMemory(item)) return false;
        if (std.mem.startsWith(u8, item.kind, "core.")) return false;
        if (std.mem.startsWith(u8, item.kind, "system.")) return false;

        const parsed = memid.MemId.parse(item.mem_id) catch return false;
        if (std.mem.startsWith(u8, parsed.name, "core.")) return false;
        if (std.mem.startsWith(u8, parsed.name, "system.")) return false;
        return true;
    }

    fn parseProviderLoopDirective(self: *RuntimeServer, raw_text: []const u8) !ProviderLoopDirective {
        const trimmed = std.mem.trim(u8, raw_text, " \t\r\n");
        if (trimmed.len == 0) {
            return .{ .action = .wait_for_user, .reason = "empty_response" };
        }

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, trimmed, .{}) catch {
            return .{
                .action = parseProviderLoopMarkers(trimmed),
                .reason = "marker_fallback",
            };
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            return .{
                .action = parseProviderLoopMarkers(trimmed),
                .reason = "non_object_fallback",
            };
        }

        const obj = parsed.value.object;
        const action_text = if (obj.get("action")) |value|
            if (value == .string) value.string else ""
        else
            "";

        const wait_for_marked = jsonObjectBool(obj, "wait_for") orelse false or
            std.ascii.eqlIgnoreCase(action_text, "wait_for");
        const followup_marked = jsonObjectBool(obj, "followup_needed") orelse false or
            std.ascii.eqlIgnoreCase(action_text, "followup_needed") or
            std.ascii.eqlIgnoreCase(action_text, "continue_reasoning") or
            std.ascii.eqlIgnoreCase(action_text, "continue");
        const task_complete_marked = jsonObjectBool(obj, "task_complete") orelse false or
            std.ascii.eqlIgnoreCase(action_text, "task_complete") or
            std.ascii.eqlIgnoreCase(action_text, "done");

        const message = if (obj.get("message")) |value| blk: {
            if (value == .string and value.string.len > 0) {
                break :blk try self.allocator.dupe(u8, value.string);
            }
            break :blk null;
        } else null;

        if (wait_for_marked) {
            return .{ .action = .wait_for_user, .message = message, .reason = "wait_for_marker" };
        }
        if (followup_marked) {
            return .{ .action = .followup_needed, .message = message, .reason = "followup_marker" };
        }
        if (task_complete_marked) {
            return .{ .action = .task_complete, .message = message, .reason = "task_complete_marker" };
        }
        if (message != null) {
            // Message-only JSON is an intent preamble, not a terminal completion signal.
            return .{ .action = .followup_needed, .message = message, .reason = "message_field" };
        }

        return .{ .action = .wait_for_user, .reason = "json_without_markers" };
    }

    fn parseStructuredToolCalls(
        self: *RuntimeServer,
        raw_text: []const u8,
        round: usize,
    ) ![]StructuredToolCall {
        const trimmed = std.mem.trim(u8, raw_text, " \t\r\n");
        if (trimmed.len == 0) return &.{};

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, trimmed, .{}) catch {
            return &.{};
        };
        defer parsed.deinit();

        if (parsed.value != .object) return &.{};
        const obj = parsed.value.object;
        const tool_calls_value = obj.get("tool_calls") orelse return &.{};
        if (tool_calls_value != .array) return &.{};
        if (tool_calls_value.array.items.len == 0) return &.{};

        var out = std.ArrayListUnmanaged(StructuredToolCall){};
        errdefer {
            for (out.items) |*call| call.deinit(self.allocator);
            out.deinit(self.allocator);
        }

        for (tool_calls_value.array.items, 0..) |entry, idx| {
            if (entry != .object) continue;
            const call_obj = entry.object;
            const name_value = call_obj.get("name") orelse continue;
            if (name_value != .string or name_value.string.len == 0) continue;

            const id = if (call_obj.get("id")) |id_value| blk: {
                if (id_value == .string and id_value.string.len > 0) {
                    break :blk try self.allocator.dupe(u8, id_value.string);
                }
                break :blk try std.fmt.allocPrint(self.allocator, "json-call-{d}-{d}", .{ round + 1, idx + 1 });
            } else try std.fmt.allocPrint(self.allocator, "json-call-{d}-{d}", .{ round + 1, idx + 1 });
            errdefer self.allocator.free(id);

            const arguments_json = if (call_obj.get("arguments")) |args_value|
                try jsonValueToOwnedSlice(self.allocator, args_value)
            else if (call_obj.get("args")) |args_value|
                try jsonValueToOwnedSlice(self.allocator, args_value)
            else
                try self.allocator.dupe(u8, "{}");
            errdefer self.allocator.free(arguments_json);

            const name = try self.allocator.dupe(u8, name_value.string);
            errdefer self.allocator.free(name);

            try out.append(self.allocator, .{
                .id = id,
                .name = name,
                .arguments_json = arguments_json,
            });
        }

        if (out.items.len == 0) {
            out.deinit(self.allocator);
            return &.{};
        }

        return out.toOwnedSlice(self.allocator);
    }

    fn finalizeProviderCompletion(
        self: *RuntimeServer,
        debug_frames: *std.ArrayListUnmanaged([]u8),
        assistant_text: []const u8,
        wait_for_user: bool,
        task_complete: bool,
    ) !ProviderCompletion {
        const final_text = try self.allocator.dupe(u8, assistant_text);
        var owned_debug_frames: ?[][]u8 = null;
        if (debug_frames.items.len > 0) {
            owned_debug_frames = try debug_frames.toOwnedSlice(self.allocator);
        } else {
            debug_frames.deinit(self.allocator);
        }
        return .{
            .assistant_text = final_text,
            .wait_for_user = wait_for_user,
            .task_complete = task_complete,
            .debug_frames = owned_debug_frames,
        };
    }

    fn jsonObjectBool(obj: std.json.ObjectMap, field: []const u8) ?bool {
        const value = obj.get(field) orelse return null;
        if (value != .bool) return null;
        return value.bool;
    }

    fn parseProviderLoopMarkers(text: []const u8) ProviderLoopAction {
        if (containsCaseInsensitive(text, "followup_needed")) return .followup_needed;
        if (containsCaseInsensitive(text, "continue_reasoning")) return .followup_needed;
        if (containsCaseInsensitive(text, "task_complete")) return .task_complete;
        if (containsCaseInsensitive(text, "wait_for")) return .wait_for_user;
        // Default fallback: no explicit tool/wait marker means wait for user.
        return .wait_for_user;
    }

    fn isImplicitWaitFallbackReason(reason: []const u8) bool {
        return std.mem.eql(u8, reason, "marker_fallback") or
            std.mem.eql(u8, reason, "non_object_fallback") or
            std.mem.eql(u8, reason, "json_without_markers");
    }

    fn isLowSignalFollowupText(text: []const u8) bool {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len == 0) return true;
        if (trimmed.len <= 3) return true;
        if (std.mem.eql(u8, trimmed, "ok")) return true;
        if (std.mem.eql(u8, trimmed, "OK")) return true;
        if (std.mem.eql(u8, trimmed, "okay")) return true;
        if (std.mem.eql(u8, trimmed, "Okay")) return true;
        if (std.mem.eql(u8, trimmed, "sure")) return true;
        if (std.mem.eql(u8, trimmed, "Sure")) return true;
        if (std.mem.eql(u8, trimmed, "got it")) return true;
        if (std.mem.eql(u8, trimmed, "Got it")) return true;
        return false;
    }

    fn isImplicitActionIntentText(text: []const u8) bool {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        if (trimmed.len == 0) return false;

        const intent_markers = [_][]const u8{
            "on it",
            "i'll",
            "i will",
            "i'm going to",
            "i am going to",
            "let me",
            "starting",
            "working on it",
        };
        if (!containsAnyIgnoreCase(trimmed, &intent_markers)) return false;

        const action_markers = [_][]const u8{
            "tool",
            "call",
            "run",
            "execute",
            "step",
            "sequence",
            "now",
        };
        return containsAnyIgnoreCase(trimmed, &action_markers);
    }

    fn toolPayloadBatchHasError(self: *RuntimeServer, payloads: []const []const u8) bool {
        for (payloads) |payload| {
            if (self.toolPayloadHasError(payload)) return true;
        }
        return false;
    }

    fn toolPayloadHasError(self: *RuntimeServer, payload: []const u8) bool {
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch {
            return std.mem.indexOf(u8, payload, "\"error\"") != null;
        };
        defer parsed.deinit();
        if (parsed.value != .object) return false;
        return parsed.value.object.get("error") != null;
    }

    fn appendToolProtocolErrorResult(
        self: *RuntimeServer,
        brain_name: []const u8,
        code: []const u8,
        message: []const u8,
        incoming_calls: usize,
    ) !void {
        const escaped_code = try protocol.jsonEscape(self.allocator, code);
        defer self.allocator.free(escaped_code);
        const escaped_message = try protocol.jsonEscape(self.allocator, message);
        defer self.allocator.free(escaped_message);
        const payload_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}},\"incoming_calls\":{d},\"constraint\":\"single_tool_call_per_round\"}}",
            .{ escaped_code, escaped_message, incoming_calls },
        );
        defer self.allocator.free(payload_json);
        var created = try self.runtime.active_memory.create(brain_name, null, "tool_result", payload_json, false, false);
        created.deinit(self.allocator);
    }

    fn appendToolResultDebugFrames(
        self: *RuntimeServer,
        debug_frames: *std.ArrayListUnmanaged([]u8),
        request_id: []const u8,
        round: usize,
        payloads: []const []const u8,
    ) !void {
        for (payloads, 0..) |payload, idx| {
            const normalized_payload = try normalizeJsonValueForDebug(self.allocator, payload);
            defer self.allocator.free(normalized_payload);
            const payload_json = try std.fmt.allocPrint(
                self.allocator,
                "{{\"round\":{d},\"result_index\":{d},\"has_error\":{},\"result\":{s}}}",
                .{ round + 1, idx, self.toolPayloadHasError(payload), normalized_payload },
            );
            defer self.allocator.free(payload_json);
            try self.appendDebugFrame(debug_frames, request_id, "runtime.tool_result", payload_json);
        }
    }

    fn containsCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
        if (needle.len == 0 or haystack.len < needle.len) return false;
        var start: usize = 0;
        while (start + needle.len <= haystack.len) : (start += 1) {
            if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
        }
        return false;
    }

    fn jsonValueToOwnedSlice(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
        return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})});
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

        var created = try self.runtime.active_memory.create(brain_name, null, "message", content_json, false, false);
        created.deinit(self.allocator);
    }

    fn appendAssistantStructuredToolCallMessage(
        self: *RuntimeServer,
        brain_name: []const u8,
        content: []const u8,
        tool_calls: []const StructuredToolCall,
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

        var created = try self.runtime.active_memory.create(brain_name, null, "message", content_json, false, false);
        created.deinit(self.allocator);
    }

    fn buildProviderStructuredToolCallDebugPayload(
        self: *RuntimeServer,
        tool_call: StructuredToolCall,
        runtime_tool_name: []const u8,
        args_with_call_id: []const u8,
        round: usize,
    ) ![]u8 {
        const escaped_id = try protocol.jsonEscape(self.allocator, tool_call.id);
        defer self.allocator.free(escaped_id);
        const escaped_provider_name = try protocol.jsonEscape(self.allocator, tool_call.name);
        defer self.allocator.free(escaped_provider_name);
        const escaped_runtime_name = try protocol.jsonEscape(self.allocator, runtime_tool_name);
        defer self.allocator.free(escaped_runtime_name);
        const escaped_args = try protocol.jsonEscape(self.allocator, args_with_call_id);
        defer self.allocator.free(escaped_args);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"round\":{d},\"tool_call\":{{\"id\":\"{s}\",\"provider_name\":\"{s}\",\"runtime_name\":\"{s}\",\"arguments\":\"{s}\"}}}}",
            .{ round, escaped_id, escaped_provider_name, escaped_runtime_name, escaped_args },
        );
    }

    fn operationTimeoutNs(self: *const RuntimeServer, operation_class: RuntimeOperationClass) u64 {
        const timeout_ms = switch (operation_class) {
            .chat => self.chat_operation_timeout_ms,
            .control => self.control_operation_timeout_ms,
        };
        return timeout_ms * std.time.ns_per_ms;
    }

    fn logProviderRequestDebug(
        self: *const RuntimeServer,
        brain_name: []const u8,
        model: ziggy_piai.types.Model,
        context: ziggy_piai.types.Context,
        options: ziggy_piai.types.StreamOptions,
    ) void {
        if (!self.log_provider_requests) return;
        const tools = context.tools orelse &.{};

        std.log.debug(
            "provider request begin provider={s} model={s} brain={s} messages={d} tools={d} reasoning={s}",
            .{
                model.provider,
                model.id,
                brain_name,
                context.messages.len,
                tools.len,
                options.reasoning orelse "default",
            },
        );
        std.log.debug("provider request system_prompt={s}", .{context.system_prompt orelse ""});

        for (context.messages, 0..) |message, idx| {
            std.log.debug(
                "provider request message[{d}] role={s} content={s}",
                .{ idx, @tagName(message.role), message.content },
            );
        }

        for (tools, 0..) |tool, idx| {
            std.log.debug(
                "provider request tool[{d}] name={s} description={s} parameters_json={s}",
                .{ idx, tool.name, tool.description, tool.parameters_json },
            );
        }

        std.log.debug("provider request end", .{});
    }
};

fn isChatLikeControlAction(action: ?[]const u8) bool {
    const control_action = action orelse "state";
    return std.mem.eql(u8, control_action, "goal") or std.mem.eql(u8, control_action, "plan");
}

fn shouldLogProviderRequests() bool {
    const env_value = std.process.getEnvVarOwned(std.heap.page_allocator, "SPIDERWEB_LOG_PROVIDER_REQUEST") catch return false;
    defer std.heap.page_allocator.free(env_value);
    return parseTruthyEnvFlag(env_value);
}

fn parseTruthyEnvFlag(raw: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(raw, "1")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return true;
    return false;
}

fn redactDebugPayload(allocator: std.mem.Allocator, payload_json: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{}) catch {
        return allocator.dupe(u8, payload_json);
    };
    defer parsed.deinit();

    redactSensitiveJsonValue(&parsed.value);
    return std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
}

fn redactSensitiveJsonValue(value: *std.json.Value) void {
    switch (value.*) {
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                if (isSensitiveJsonKey(entry.key_ptr.*)) {
                    entry.value_ptr.* = .{ .string = "[redacted]" };
                } else {
                    redactSensitiveJsonValue(entry.value_ptr);
                }
            }
        },
        .array => |*arr| {
            for (arr.items) |*child| {
                redactSensitiveJsonValue(child);
            }
        },
        else => {},
    }
}

fn isSensitiveJsonKey(key: []const u8) bool {
    if (key.len == 0) return false;

    if (std.ascii.eqlIgnoreCase(key, "api_key")) return true;
    if (std.ascii.eqlIgnoreCase(key, "apikey")) return true;
    if (std.ascii.eqlIgnoreCase(key, "authorization")) return true;
    if (std.ascii.eqlIgnoreCase(key, "auth_token")) return true;
    if (std.ascii.eqlIgnoreCase(key, "token")) return true;
    if (std.ascii.eqlIgnoreCase(key, "secret")) return true;
    if (std.ascii.eqlIgnoreCase(key, "password")) return true;
    if (endsWithAsciiIgnoreCase(key, "_token")) return true;
    if (endsWithAsciiIgnoreCase(key, "-token")) return true;
    if (endsWithAsciiIgnoreCase(key, "_secret")) return true;
    if (endsWithAsciiIgnoreCase(key, "-secret")) return true;
    if (endsWithAsciiIgnoreCase(key, "_api_key")) return true;
    if (endsWithAsciiIgnoreCase(key, "-api-key")) return true;

    return false;
}

fn endsWithAsciiIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (suffix.len > haystack.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

fn normalizeJsonValueForDebug(allocator: std.mem.Allocator, raw_json: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{}) catch {
        const escaped = try protocol.jsonEscape(allocator, raw_json);
        defer allocator.free(escaped);
        return std.fmt.allocPrint(allocator, "\"{s}\"", .{escaped});
    };
    defer parsed.deinit();

    return std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
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

fn markFreedPtr(
    allocator: std.mem.Allocator,
    freed_ptrs: *std.AutoHashMapUnmanaged(usize, void),
    addr: usize,
) bool {
    if (freed_ptrs.contains(addr)) return false;
    freed_ptrs.put(allocator, addr, {}) catch return false;
    return true;
}

fn freeBytesOnce(
    allocator: std.mem.Allocator,
    freed_ptrs: *std.AutoHashMapUnmanaged(usize, void),
    bytes: []const u8,
) void {
    if (bytes.len == 0) return;
    const addr = @intFromPtr(bytes.ptr);
    if (!markFreedPtr(allocator, freed_ptrs, addr)) return;
    allocator.free(bytes);
}

fn freeToolCallsOnce(
    allocator: std.mem.Allocator,
    freed_ptrs: *std.AutoHashMapUnmanaged(usize, void),
    tool_calls: []const ziggy_piai.types.ToolCall,
) void {
    if (tool_calls.len == 0) return;
    const addr = @intFromPtr(tool_calls.ptr);
    if (!markFreedPtr(allocator, freed_ptrs, addr)) return;
    allocator.free(tool_calls);
}

fn deinitAssistantMessageDedup(
    allocator: std.mem.Allocator,
    msg: *ziggy_piai.types.AssistantMessage,
    freed_ptrs: *std.AutoHashMapUnmanaged(usize, void),
) void {
    freeBytesOnce(allocator, freed_ptrs, msg.text);
    freeBytesOnce(allocator, freed_ptrs, msg.thinking);
    if (msg.error_message) |value| freeBytesOnce(allocator, freed_ptrs, value);
    for (msg.tool_calls) |tool_call| {
        freeBytesOnce(allocator, freed_ptrs, tool_call.id);
        freeBytesOnce(allocator, freed_ptrs, tool_call.name);
        freeBytesOnce(allocator, freed_ptrs, tool_call.arguments_json);
    }
    freeToolCallsOnce(allocator, freed_ptrs, msg.tool_calls);
}

fn deinitAssistantEvents(
    allocator: std.mem.Allocator,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) void {
    var freed_ptrs = std.AutoHashMapUnmanaged(usize, void){};
    defer freed_ptrs.deinit(allocator);

    for (events.items) |*event| {
        switch (event.*) {
            .start => |*msg| deinitAssistantMessageDedup(allocator, msg, &freed_ptrs),
            .done => |*msg| deinitAssistantMessageDedup(allocator, msg, &freed_ptrs),
            .text_delta => |*delta| freeBytesOnce(allocator, &freed_ptrs, delta.delta),
            .text_end => |*end| freeBytesOnce(allocator, &freed_ptrs, end.content),
            .thinking_delta => |*delta| freeBytesOnce(allocator, &freed_ptrs, delta.delta),
            .thinking_end => |*end| freeBytesOnce(allocator, &freed_ptrs, end.content),
            .toolcall_delta => |*delta| freeBytesOnce(allocator, &freed_ptrs, delta.delta),
            .toolcall_end => |*end| {
                freeBytesOnce(allocator, &freed_ptrs, end.tool_call.id);
                freeBytesOnce(allocator, &freed_ptrs, end.tool_call.name);
                freeBytesOnce(allocator, &freed_ptrs, end.tool_call.arguments_json);
            },
            .err => |value| freeBytesOnce(allocator, &freed_ptrs, value),
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

test "runtime_server: parseTruthyEnvFlag accepts common truthy values" {
    try std.testing.expect(parseTruthyEnvFlag("1"));
    try std.testing.expect(parseTruthyEnvFlag("true"));
    try std.testing.expect(parseTruthyEnvFlag("TRUE"));
    try std.testing.expect(parseTruthyEnvFlag("yes"));
    try std.testing.expect(parseTruthyEnvFlag("on"));
}

test "runtime_server: deinitAssistantEvents deduplicates shared tool-call buffers" {
    const allocator = std.testing.allocator;

    var events = std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent).init(allocator);
    defer events.deinit();

    const shared_id = try allocator.dupe(u8, "call-shared");
    const shared_name = try allocator.dupe(u8, "file_list");
    const shared_args = try allocator.dupe(u8, "{\"path\":\".\"}");

    const tool_calls = try allocator.alloc(ziggy_piai.types.ToolCall, 1);
    tool_calls[0] = .{
        .id = shared_id,
        .name = shared_name,
        .arguments_json = shared_args,
    };

    try events.append(.{
        .toolcall_end = .{
            .tool_call = .{
                .id = shared_id,
                .name = shared_name,
                .arguments_json = shared_args,
            },
        },
    });
    try events.append(.{
        .done = .{
            .text = try allocator.dupe(u8, ""),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = tool_calls,
            .api = "responses",
            .provider = "openai-codex",
            .model = "gpt-5.3-codex",
            .usage = .{},
            .stop_reason = .tool_use,
            .error_message = null,
        },
    });

    deinitAssistantEvents(allocator, &events);
}

test "runtime_server: parseTruthyEnvFlag rejects falsey values" {
    try std.testing.expect(!parseTruthyEnvFlag(""));
    try std.testing.expect(!parseTruthyEnvFlag("0"));
    try std.testing.expect(!parseTruthyEnvFlag("false"));
    try std.testing.expect(!parseTruthyEnvFlag("off"));
}

test "runtime_server: redactDebugPayload masks secret fields only" {
    const allocator = std.testing.allocator;
    const payload =
        \\{
        \\  "api_key":"abc123",
        \\  "authorization":"Bearer value",
        \\  "auth_token":"token-value",
        \\  "session_id":"visible",
        \\  "nested":{"github_token":"gh_abc","safe":"ok"},
        \\  "items":[{"secret":"x"},{"name":"visible"}]
        \\}
    ;
    const redacted = try redactDebugPayload(allocator, payload);
    defer allocator.free(redacted);

    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"api_key\":\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"authorization\":\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"auth_token\":\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"github_token\":\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"secret\":\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"session_id\":\"visible\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"safe\":\"ok\"") != null);
}

test "runtime_server: redactDebugPayload masks sensitive suffixes on long keys" {
    const allocator = std.testing.allocator;
    const long_prefix = try allocator.alloc(u8, 140);
    defer allocator.free(long_prefix);
    @memset(long_prefix, 'a');

    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"{s}_token\":\"secret-value\",\"safe\":\"ok\"}}",
        .{long_prefix},
    );
    defer allocator.free(payload);

    const redacted = try redactDebugPayload(allocator, payload);
    defer allocator.free(redacted);

    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"secret-value\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"[redacted]\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "\"safe\":\"ok\"") != null);
}

fn buildTaskCompleteOutput(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    const escaped_message = try protocol.jsonEscape(allocator, message);
    defer allocator.free(escaped_message);
    return std.fmt.allocPrint(
        allocator,
        "{{\"task_complete\":true,\"message\":\"{s}\"}}",
        .{escaped_message},
    );
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
    const output = try buildTaskCompleteOutput(allocator, "mock provider response");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamAssertsFreshActiveSnapshot(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    try std.testing.expectEqual(@as(usize, 1), context.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "core.stale_provider_entry") == null);

    const output = try buildTaskCompleteOutput(allocator, "fresh snapshot response");
    try events.append(.{ .done = .{
        .text = output,
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
var mockSensitiveToolLoopCallCount: usize = 0;
var mockJsonToolEnvelopeCallCount: usize = 0;
var mockJsonToolEnvelopeImplicitWaitCallCount: usize = 0;
var mockJsonToolEnvelopeErrorWaitCallCount: usize = 0;
var mockJsonToolEnvelopeMultiToolBatchCount: usize = 0;
var mockJsonToolEnvelopeMultiToolBatchPlainTextCount: usize = 0;
var mockPlainTextIntentFollowupCallCount: usize = 0;
var mockJsonMessageOnlyFollowupCallCount: usize = 0;
var mockRateLimitCallCount: usize = 0;
var mockAuthFailureCallCount: usize = 0;
var testBeforeCompleteStepHook: ?*const fn (*RuntimeServer, []const u8) anyerror!void = null;
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
    const output = try buildTaskCompleteOutput(allocator, "captured provider response");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockWorldToolOk(allocator: std.mem.Allocator, _: std.json.ObjectMap) tool_registry.ToolExecutionResult {
    const payload = allocator.dupe(u8, "{\"ok\":true}") catch {
        const msg = allocator.dupe(u8, "out of memory") catch @panic("out of memory");
        return .{ .failure = .{ .code = .execution_failed, .message = msg } };
    };
    return .{ .success = .{ .payload_json = payload } };
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
            .name = try allocator.dupe(u8, "file_list"),
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
    const output = try buildTaskCompleteOutput(allocator, "tool loop complete");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithJsonToolEnvelope(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonToolEnvelopeCallCount == 0) {
        mockJsonToolEnvelopeCallCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_list","arguments":{"path":"src"}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    try std.testing.expectEqual(@as(usize, 1), context.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"tool_result\"") != null);
    const output = try buildTaskCompleteOutput(allocator, "json tool loop complete");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithJsonToolEnvelopeImplicitWait(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonToolEnvelopeImplicitWaitCallCount == 0) {
        mockJsonToolEnvelopeImplicitWaitCallCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_list","arguments":{"path":"src"}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    if (mockJsonToolEnvelopeImplicitWaitCallCount == 1) {
        mockJsonToolEnvelopeImplicitWaitCallCount += 1;
        try std.testing.expectEqual(@as(usize, 1), context.messages.len);
        try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"tool_result\"") != null);
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, "ok"),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    const output = try buildTaskCompleteOutput(allocator, "json tool loop recovered complete");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithPlainTextIntentThenJsonTool(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockPlainTextIntentFollowupCallCount == 0) {
        mockPlainTextIntentFollowupCallCount += 1;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, "On it. I'll execute the tool call now."),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    if (mockPlainTextIntentFollowupCallCount == 1) {
        mockPlainTextIntentFollowupCallCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_list","arguments":{"path":"src"}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    try std.testing.expectEqual(@as(usize, 1), context.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"tool_result\"") != null);

    const output = try buildTaskCompleteOutput(allocator, "plain-text intent recovered complete");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithJsonToolEnvelopeErrorThenWait(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonToolEnvelopeErrorWaitCallCount == 0) {
        mockJsonToolEnvelopeErrorWaitCallCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_read","arguments":{"path":"missing.txt","max_bytes":32}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    if (mockJsonToolEnvelopeErrorWaitCallCount == 1) {
        mockJsonToolEnvelopeErrorWaitCallCount += 1;
        try std.testing.expectEqual(@as(usize, 1), context.messages.len);
        try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"tool_result\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"error\"") != null);
        const wait_json = "{\"action\":\"wait_for\"}";
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, wait_json),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    const output = try buildTaskCompleteOutput(allocator, "reported tool failure");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithJsonMultiToolBatch(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonToolEnvelopeMultiToolBatchCount == 0) {
        mockJsonToolEnvelopeMultiToolBatchCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_list","arguments":{"path":".","max_entries":50}},{"name":"talk_user","arguments":{"message":"planning message"}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    try std.testing.expectEqual(@as(usize, 1), context.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"invalid_tool_batch\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "planning message") != null);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"file_list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"talk_user\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"entries\"") == null);

    const output = try buildTaskCompleteOutput(allocator, "multi-tool batch rejected and corrected");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithJsonMultiToolBatchThenPlainText(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    context: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonToolEnvelopeMultiToolBatchPlainTextCount == 0) {
        mockJsonToolEnvelopeMultiToolBatchPlainTextCount += 1;
        const envelope =
            \\{"action":"act","tool_calls":[{"name":"file_list","arguments":{"path":".","max_entries":50}},{"name":"file_read","arguments":{"path":"CORE.md","max_bytes":200}}]}
        ;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, envelope),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    if (mockJsonToolEnvelopeMultiToolBatchPlainTextCount == 1) {
        mockJsonToolEnvelopeMultiToolBatchPlainTextCount += 1;
        try std.testing.expectEqual(@as(usize, 1), context.messages.len);
        try std.testing.expect(std.mem.indexOf(u8, context.messages[0].content, "\"invalid_tool_batch\"") != null);
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, "Got it — I need to do this one tool at a time."),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    mockJsonToolEnvelopeMultiToolBatchPlainTextCount += 1;
    const output = try buildTaskCompleteOutput(allocator, "recovered after plain-text fallback");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWithSensitiveToolLoop(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockSensitiveToolLoopCallCount == 0) {
        mockSensitiveToolLoopCallCount += 1;
        const tool_calls = try allocator.alloc(ziggy_piai.types.ToolCall, 1);
        tool_calls[0] = .{
            .id = try allocator.dupe(u8, "call-sensitive-1"),
            .name = try allocator.dupe(u8, "file_list"),
            .arguments_json = try allocator.dupe(u8, "{\"path\":\"src\",\"api_key\":\"sensitive-key\"}"),
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

    const output = try buildTaskCompleteOutput(allocator, "sensitive tool loop complete");
    try events.append(.{ .done = .{
        .text = output,
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
            .name = try allocator.dupe(u8, "file_list"),
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

fn mockProviderStreamByModelStreamFailure(
    _: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    _: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    return error.CompleteErrorUnavailable;
}

fn mockProviderStreamByModelRateLimited(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    mockRateLimitCallCount += 1;
    try events.append(.{ .err = try allocator.dupe(u8, "Request failed with status 429. Retry-After: 1") });
}

fn mockProviderStreamByModelAuthFailed(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    mockAuthFailureCallCount += 1;
    try events.append(.{ .err = try allocator.dupe(u8, "Request failed with status 401 unauthorized") });
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
    const output = try buildTaskCompleteOutput(allocator, "slow provider response");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelVerySlow(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    std.Thread.sleep(200 * std.time.ns_per_ms);
    const output = try buildTaskCompleteOutput(allocator, "very slow provider response");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelWaitWithMessage(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    _: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    const payload = "{\"action\":\"wait_for\",\"message\":\"Please provide your API key\"}";
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, payload),
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

fn mockProviderStreamByModelWithJsonMessageOnlyThenTaskComplete(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    if (mockJsonMessageOnlyFollowupCallCount == 0) {
        mockJsonMessageOnlyFollowupCallCount += 1;
        try events.append(.{ .done = .{
            .text = try allocator.dupe(u8, "{\"message\":\"I'll do that now.\"}"),
            .thinking = try allocator.dupe(u8, ""),
            .tool_calls = &.{},
            .api = model.api,
            .provider = model.provider,
            .model = model.id,
            .usage = .{},
            .stop_reason = .stop,
            .error_message = null,
        } });
        return;
    }

    mockJsonMessageOnlyFollowupCallCount += 1;
    const output = try buildTaskCompleteOutput(allocator, "json message-only recovered complete");
    try events.append(.{ .done = .{
        .text = output,
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

fn mockProviderStreamByModelPlainTextNoMarkers(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "plain text without task markers"),
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

fn mockProviderStreamByModelPlainTextUnicode(
    allocator: std.mem.Allocator,
    _: *std.http.Client,
    _: *ziggy_piai.api_registry.ApiRegistry,
    model: ziggy_piai.types.Model,
    _: ziggy_piai.types.Context,
    _: ziggy_piai.types.StreamOptions,
    events: *std.array_list.Managed(ziggy_piai.types.AssistantMessageEvent),
) anyerror!void {
    try events.append(.{ .done = .{
        .text = try allocator.dupe(u8, "Hello! 👋"),
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

fn cancelRunBeforeCompleteStepHook(server: *RuntimeServer, run_id: []const u8) anyerror!void {
    // One-shot hook used by tests to inject cancellation in the completion window.
    testBeforeCompleteStepHook = null;
    const cancel_req = try std.fmt.allocPrint(
        server.allocator,
        "{{\"id\":\"req-run-cancel-complete-race\",\"type\":\"agent.run.cancel\",\"action\":\"{s}\"}}",
        .{run_id},
    );
    defer server.allocator.free(cancel_req);

    const cancel_rsp = try server.handleMessage(cancel_req);
    defer server.allocator.free(cancel_rsp);
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

test "runtime_server: raw text payload is treated as session.send" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const response = try server.handleMessage("hello runtime");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "hello runtime") != null);
}

test "runtime_server: agent.run.start executes one deterministic step and returns run frames" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-run-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const frames = try server.handleMessageFrames("{\"id\":\"req-run-start\",\"type\":\"agent.run.start\",\"content\":\"build reliable loop\"}");
    defer deinitResponseFrames(allocator, frames);

    try std.testing.expect(frames.len >= 2);
    try std.testing.expect(std.mem.indexOf(u8, frames[0], "\"type\":\"agent.run.ack\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, frames[1], "\"type\":\"agent.run.event\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, frames[0], .{});
    defer parsed.deinit();
    const run_id = parsed.value.object.get("run_id").?.string;
    try std.testing.expect(run_id.len > 0);
}

test "runtime_server: agent.run status/events/list operate on created run" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-run-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const start_frames = try server.handleMessageFrames("{\"id\":\"req-run-start-2\",\"type\":\"agent.run.start\",\"content\":\"analyze codebase\"}");
    defer deinitResponseFrames(allocator, start_frames);

    var ack = try std.json.parseFromSlice(std.json.Value, allocator, start_frames[0], .{});
    defer ack.deinit();
    const run_id = ack.value.object.get("run_id").?.string;

    const status = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-status\",\"type\":\"agent.run.status\",\"action\":\"{s}\"}}", .{run_id});
    defer allocator.free(status);
    const status_response = try server.handleMessage(status);
    defer allocator.free(status_response);
    try std.testing.expect(std.mem.indexOf(u8, status_response, "\"type\":\"agent.run.state\"") != null);

    const events = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-events\",\"type\":\"agent.run.events\",\"action\":\"{s}\",\"content\":\"10\"}}", .{run_id});
    defer allocator.free(events);
    const events_response = try server.handleMessage(events);
    defer allocator.free(events_response);
    try std.testing.expect(std.mem.indexOf(u8, events_response, "\"type\":\"agent.run.event\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, events_response, "\"event_type\":\"run.events\"") != null);

    const list_response = try server.handleMessage("{\"id\":\"req-run-list\",\"type\":\"agent.run.list\"}");
    defer allocator.free(list_response);
    try std.testing.expect(std.mem.indexOf(u8, list_response, "\"event_type\":\"run.list\"") != null);
}

test "runtime_server: agent.run.start marks completed when provider emits task_complete" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModel;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-provider", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const frames = try server.handleMessageFrames("{\"id\":\"req-run-start-provider\",\"type\":\"agent.run.start\",\"content\":\"finish task\"}");
    defer deinitResponseFrames(allocator, frames);

    var run_id: ?[]const u8 = null;
    var saw_completed_state = false;
    for (frames) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"agent.run.ack\"") != null) {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
            defer parsed.deinit();
            run_id = parsed.value.object.get("run_id").?.string;
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"agent.run.state\"") != null and
            std.mem.indexOf(u8, payload, "\"state\":\"completed\"") != null)
        {
            saw_completed_state = true;
        }
    }

    try std.testing.expect(run_id != null);
    try std.testing.expect(saw_completed_state);

    const status_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-status-provider\",\"type\":\"agent.run.status\",\"action\":\"{s}\"}}", .{run_id.?});
    defer allocator.free(status_req);
    const status = try server.handleMessage(status_req);
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"state\":\"completed\"") != null);
}

test "runtime_server: agent.run.start preserves wait_for directive message" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWaitWithMessage;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-provider-wait", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const frames = try server.handleMessageFrames("{\"id\":\"req-run-start-provider-wait\",\"type\":\"agent.run.start\",\"content\":\"continue\"}");
    defer deinitResponseFrames(allocator, frames);

    var saw_wait_message = false;
    var saw_fallback_ok = false;
    var saw_waiting_state = false;
    for (frames) |payload| {
        if (std.mem.indexOf(u8, payload, "Please provide your API key") != null) saw_wait_message = true;
        if (std.mem.indexOf(u8, payload, "\"content\":\"ok\"") != null) saw_fallback_ok = true;
        if (std.mem.indexOf(u8, payload, "\"type\":\"agent.run.state\"") != null and
            std.mem.indexOf(u8, payload, "\"state\":\"waiting_for_user\"") != null)
        {
            saw_waiting_state = true;
        }
    }

    try std.testing.expect(saw_wait_message);
    try std.testing.expect(!saw_fallback_ok);
    try std.testing.expect(saw_waiting_state);
}

test "runtime_server: run step fails and returns chat error frame when provider fails" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelError;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-provider-error", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const frames = try server.handleMessageFrames("{\"id\":\"req-run-start-error\",\"type\":\"agent.run.start\",\"content\":\"finish task\"}");
    defer deinitResponseFrames(allocator, frames);

    var run_id: ?[]const u8 = null;
    var saw_error_frame = false;
    var saw_error_request_match = false;
    var saw_failed_state = false;
    for (frames) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"agent.run.ack\"") != null) {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
            defer parsed.deinit();
            run_id = parsed.value.object.get("run_id").?.string;
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"error\"") != null and
            std.mem.indexOf(u8, payload, "\"code\":\"provider_unavailable\"") != null)
        {
            saw_error_frame = true;
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
            defer parsed.deinit();
            const request = parsed.value.object.get("request").?.string;
            if (std.mem.eql(u8, request, "req-run-start-error")) {
                saw_error_request_match = true;
            }
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"agent.run.state\"") != null and
            std.mem.indexOf(u8, payload, "\"state\":\"failed\"") != null)
        {
            saw_failed_state = true;
        }
    }

    try std.testing.expect(run_id != null);
    try std.testing.expect(saw_error_frame);
    try std.testing.expect(saw_error_request_match);
    try std.testing.expect(saw_failed_state);

    const status_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-status-error\",\"type\":\"agent.run.status\",\"action\":\"{s}\"}}", .{run_id.?});
    defer allocator.free(status_req);
    const status = try server.handleMessage(status_req);
    defer allocator.free(status);
    try std.testing.expect(std.mem.indexOf(u8, status, "\"state\":\"failed\"") != null);
}

test "runtime_server: run resume without input keeps paused state" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-run-resume", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const start_frames = try server.handleMessageFrames("{\"id\":\"req-run-start-resume\",\"type\":\"agent.run.start\",\"content\":\"one step\"}");
    defer deinitResponseFrames(allocator, start_frames);
    try std.testing.expect(start_frames.len >= 1);

    var ack = try std.json.parseFromSlice(std.json.Value, allocator, start_frames[0], .{});
    defer ack.deinit();
    const run_id = ack.value.object.get("run_id").?.string;

    const pause_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-pause-resume\",\"type\":\"agent.run.pause\",\"action\":\"{s}\"}}", .{run_id});
    defer allocator.free(pause_req);
    const pause_rsp = try server.handleMessage(pause_req);
    defer allocator.free(pause_rsp);
    try std.testing.expect(std.mem.indexOf(u8, pause_rsp, "\"state\":\"paused\"") != null);

    const resume_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-resume-empty\",\"type\":\"agent.run.resume\",\"action\":\"{s}\"}}", .{run_id});
    defer allocator.free(resume_req);
    const resume_rsp = try server.handleMessage(resume_req);
    defer allocator.free(resume_rsp);
    try std.testing.expect(std.mem.indexOf(u8, resume_rsp, "\"type\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resume_rsp, "NoPendingInput") != null);

    const status_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-status-resume\",\"type\":\"agent.run.status\",\"action\":\"{s}\"}}", .{run_id});
    defer allocator.free(status_req);
    const status_rsp = try server.handleMessage(status_req);
    defer allocator.free(status_rsp);
    try std.testing.expect(std.mem.indexOf(u8, status_rsp, "\"state\":\"paused\"") != null);
}

test "runtime_server: extractRunStepFrameResult uses final session.receive content" {
    const allocator = std.testing.allocator;

    var frames = std.ArrayListUnmanaged([]u8){};
    defer {
        for (frames.items) |payload| allocator.free(payload);
        frames.deinit(allocator);
    }

    try frames.append(allocator, try allocator.dupe(u8, "{\"type\":\"session.receive\",\"content\":\"intermediate\"}"));
    try frames.append(allocator, try allocator.dupe(u8, "{\"type\":\"agent.run.event\",\"event_type\":\"assistant.output\"}"));
    try frames.append(allocator, try allocator.dupe(u8, "{\"type\":\"session.receive\",\"content\":\"final\"}"));

    var extracted = try RuntimeServer.extractRunStepFrameResult(allocator, frames.items);
    defer extracted.deinit(allocator);

    try std.testing.expectEqualStrings("final", extracted.assistant_content);
    try std.testing.expect(extracted.error_message == null);
}

test "runtime_server: cancelled run step aborts and requeues input" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-run-cancel", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    var started = try server.runs.start("cancel flow");
    defer started.deinit(allocator);

    const job = try server.createJob(.agent_run_step, "req-run-cancelled", null, null, false);
    defer server.destroyJob(job);

    job.result_mutex.lock();
    job.cancelled = true;
    job.result_mutex.unlock();

    try std.testing.expectError(
        RuntimeServerError.RuntimeJobCancelled,
        server.runSingleStep(job, "req-run-cancelled", started.run_id, null, false, false),
    );

    var snapshot = try server.runs.get(started.run_id);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(run_engine.RunState.paused, snapshot.state);

    var resumed = try server.runs.beginResumedStep(started.run_id, null);
    defer resumed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), resumed.step_count);
    try std.testing.expectEqualStrings("cancel flow", resumed.input);
}

test "runtime_server: agent.run.cancel preempts active run step" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelVerySlow;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-preempt", .{
        .chat_operation_timeout_ms = 2_000,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var started = try server.runs.start(null);
    defer started.deinit(allocator);

    const step_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-step-preempt\",\"type\":\"agent.run.step\",\"action\":\"{s}\",\"content\":\"do work\"}}", .{started.run_id});
    defer allocator.free(step_req);

    const StepThread = struct {
        server: *RuntimeServer,
        request: []const u8,
        response: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            ctx.response = ctx.server.handleMessage(ctx.request) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };

    var worker = StepThread{
        .server = server,
        .request = step_req,
    };
    const thread = try std.Thread.spawn(.{}, StepThread.run, .{&worker});

    var saw_active = false;
    var wait_ms: usize = 0;
    while (wait_ms < 500) : (wait_ms += 5) {
        server.run_step_mutex.lock();
        const active = server.active_run_steps.contains(started.run_id);
        server.run_step_mutex.unlock();
        if (active) {
            saw_active = true;
            break;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(saw_active);

    const cancel_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-cancel-preempt\",\"type\":\"agent.run.cancel\",\"action\":\"{s}\"}}", .{started.run_id});
    defer allocator.free(cancel_req);
    const cancel_rsp = try server.handleMessage(cancel_req);
    defer allocator.free(cancel_rsp);
    try std.testing.expect(std.mem.indexOf(u8, cancel_rsp, "\"type\":\"agent.run.state\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cancel_rsp, "\"state\":\"cancelled\"") != null);

    thread.join();
    try std.testing.expect(worker.err == null);
    try std.testing.expect(worker.response != null);
    const step_rsp = worker.response.?;
    defer allocator.free(step_rsp);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "\"code\":\"runtime_cancelled\"") != null);

    var snapshot = try server.runs.get(started.run_id);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(run_engine.RunState.cancelled, snapshot.state);
}

test "runtime_server: cancel race before completeStep returns runtime_cancelled" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModel;

    testBeforeCompleteStepHook = cancelRunBeforeCompleteStepHook;
    defer testBeforeCompleteStepHook = null;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-cancel-complete-race", .{
        .chat_operation_timeout_ms = 2_000,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var started = try server.runs.start(null);
    defer started.deinit(allocator);

    const step_req = try std.fmt.allocPrint(
        allocator,
        "{{\"id\":\"req-run-step-complete-race\",\"type\":\"agent.run.step\",\"action\":\"{s}\",\"content\":\"do work\"}}",
        .{started.run_id},
    );
    defer allocator.free(step_req);

    const step_rsp = try server.handleMessage(step_req);
    defer allocator.free(step_rsp);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "\"type\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "\"code\":\"runtime_cancelled\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "InvalidState") == null);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "\"code\":\"execution_failed\"") == null);

    var snapshot = try server.runs.get(started.run_id);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(run_engine.RunState.cancelled, snapshot.state);
}

test "runtime_server: agent.run.pause is rejected while run step is active" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelVerySlow;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-pause-active", .{
        .chat_operation_timeout_ms = 2_000,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var started = try server.runs.start(null);
    defer started.deinit(allocator);

    const step_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-step-pause-active\",\"type\":\"agent.run.step\",\"action\":\"{s}\",\"content\":\"do work\"}}", .{started.run_id});
    defer allocator.free(step_req);

    const StepThread = struct {
        server: *RuntimeServer,
        request: []const u8,
        response: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            ctx.response = ctx.server.handleMessage(ctx.request) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };

    var worker = StepThread{
        .server = server,
        .request = step_req,
    };
    const thread = try std.Thread.spawn(.{}, StepThread.run, .{&worker});

    var saw_active = false;
    var wait_ms: usize = 0;
    while (wait_ms < 500) : (wait_ms += 5) {
        if (server.isRunStepActive(started.run_id)) {
            saw_active = true;
            break;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(saw_active);

    const pause_req = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-pause-active\",\"type\":\"agent.run.pause\",\"action\":\"{s}\"}}", .{started.run_id});
    defer allocator.free(pause_req);
    const pause_rsp = try server.handleMessage(pause_req);
    defer allocator.free(pause_rsp);
    try std.testing.expect(std.mem.indexOf(u8, pause_rsp, "\"type\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pause_rsp, "\"code\":\"execution_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, pause_rsp, "run step already active") != null);

    thread.join();
    try std.testing.expect(worker.err == null);
    try std.testing.expect(worker.response != null);
    const step_rsp = worker.response.?;
    defer allocator.free(step_rsp);
    try std.testing.expect(std.mem.indexOf(u8, step_rsp, "\"state\":\"completed\"") != null);
}

test "runtime_server: concurrent run.step requests reject second active step" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelVerySlow;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-run-concurrent-step", .{
        .chat_operation_timeout_ms = 2_000,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var started = try server.runs.start(null);
    defer started.deinit(allocator);

    const step_req_1 = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-step-concurrent-1\",\"type\":\"agent.run.step\",\"action\":\"{s}\",\"content\":\"first\"}}", .{started.run_id});
    defer allocator.free(step_req_1);
    const step_req_2 = try std.fmt.allocPrint(allocator, "{{\"id\":\"req-run-step-concurrent-2\",\"type\":\"agent.run.step\",\"action\":\"{s}\",\"content\":\"second\"}}", .{started.run_id});
    defer allocator.free(step_req_2);

    const StepThread = struct {
        server: *RuntimeServer,
        request: []const u8,
        response: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(ctx: *@This()) void {
            ctx.response = ctx.server.handleMessage(ctx.request) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };

    var worker = StepThread{
        .server = server,
        .request = step_req_1,
    };
    const thread = try std.Thread.spawn(.{}, StepThread.run, .{&worker});

    var saw_active = false;
    var wait_ms: usize = 0;
    while (wait_ms < 500) : (wait_ms += 5) {
        if (server.isRunStepActive(started.run_id)) {
            saw_active = true;
            break;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(saw_active);

    const second_rsp = try server.handleMessage(step_req_2);
    defer allocator.free(second_rsp);
    try std.testing.expect(std.mem.indexOf(u8, second_rsp, "\"type\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, second_rsp, "\"code\":\"execution_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, second_rsp, "run step already active") != null);

    thread.join();
    try std.testing.expect(worker.err == null);
    try std.testing.expect(worker.response != null);
    const first_rsp = worker.response.?;
    defer allocator.free(first_rsp);
    try std.testing.expect(std.mem.indexOf(u8, first_rsp, "\"state\":\"completed\"") != null);
}

test "runtime_server: empty ltm config in tests provisions sqlite-backed runtime" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    try std.testing.expect(server.runtime.ltm_store != null);
    try std.testing.expect(server.test_ltm_directory != null);
}

test "runtime_server: base core prompt renders first without mem_id prefix" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    try server.runtime.refreshCorePrompt("primary");
    const prompt = try server.buildCoreSystemPrompt("primary");
    defer allocator.free(prompt);

    const base_idx = std.mem.indexOf(u8, prompt, "# CORE.md - Runtime Contract (Authoritative)") orelse return error.TestUnexpectedResult;
    const soul_idx = std.mem.indexOf(u8, prompt, "SOUL.md") orelse return error.TestUnexpectedResult;

    try std.testing.expect(base_idx < soul_idx);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "core.system.base_instructions") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "core.system.capabilities") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "core.system.identity_guidance") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "[") != null);
}

test "runtime_server: legacy transient core prompt entries are excluded from system prompt" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    var legacy_capabilities = try server.runtime.active_memory.create(
        "primary",
        "core.system.capabilities",
        "core.system_prompt",
        "\"legacy capabilities\"",
        true,
        true,
    );
    defer legacy_capabilities.deinit(allocator);

    var legacy_guidance = try server.runtime.active_memory.create(
        "primary",
        "core.system.identity_guidance",
        "core.system_prompt",
        "\"legacy guidance\"",
        true,
        true,
    );
    defer legacy_guidance.deinit(allocator);

    const prompt = try server.buildCoreSystemPrompt("primary");
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "legacy capabilities") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "legacy guidance") == null);
}

test "runtime_server: provider active memory prompt excludes core memory entries" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    try server.runtime.refreshCorePrompt("primary");
    var user_message = try server.runtime.active_memory.create(
        "primary",
        "message.user",
        "message",
        "{\"role\":\"user\",\"content\":\"hello runtime\"}",
        false,
        false,
    );
    defer user_message.deinit(allocator);

    const prompt = try server.buildProviderActiveMemoryPrompt("primary");
    defer allocator.free(prompt);

    try std.testing.expect(std.mem.indexOf(u8, prompt, "\"kind\":\"message\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "hello runtime") != null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "\"kind\":\"core.system_prompt\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "\"kind\":\"core.base_prompt\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "core.system.agent_id") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "system.core") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "system.soul") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "<active_memory_state>") == null);
    try std.testing.expect(std.mem.indexOf(u8, prompt, "Use only this state as conversation context.") == null);
}

test "runtime_server: provider instructions include dynamic info board without persisting it" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-test", .{ .ltm_directory = "", .ltm_filename = "" });
    defer server.destroy();

    const active_memory_prompt = "<active_memory_state>{}</active_memory_state>";
    const instructions = try server.buildProviderInstructions("primary", active_memory_prompt, 128_000, 0);
    defer allocator.free(instructions);

    const board_idx = std.mem.indexOf(u8, instructions, "## Dynamic Info Board") orelse return error.TestUnexpectedResult;
    const soul_idx = std.mem.indexOf(u8, instructions, "SOUL.md") orelse return error.TestUnexpectedResult;
    try std.testing.expect(board_idx > soul_idx);
    try std.testing.expect(std.mem.indexOf(u8, instructions, "approximate_context_used: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, instructions, "date_time_utc: ") != null);

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);

    for (snapshot) |item| {
        try std.testing.expect(std.mem.indexOf(u8, item.content_json, "Dynamic Info Board") == null);
    }
}

test "runtime_server: wait_for tool schema includes events items" {
    const allocator = std.testing.allocator;
    const specs = try RuntimeServer.buildProviderBrainTools(allocator);
    defer tool_registry.deinitProviderTools(allocator, specs);

    for (specs) |spec| {
        if (!std.mem.eql(u8, spec.name, "wait_for")) continue;
        try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"events\":{\"type\":\"array\",\"items\":{\"type\":\"object\"}}") != null);
        return;
    }

    return error.TestUnexpectedResult;
}

test "runtime_server: provider tool schemas include optional args and flexible content" {
    const allocator = std.testing.allocator;
    const specs = try RuntimeServer.buildProviderBrainTools(allocator);
    defer tool_registry.deinitProviderTools(allocator, specs);

    var saw_memory_load = false;
    var saw_memory_versions = false;
    var saw_memory_search = false;
    var saw_memory_create = false;
    var saw_memory_mutate = false;

    for (specs) |spec| {
        if (std.mem.eql(u8, spec.name, "memory_load")) {
            saw_memory_load = true;
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"version\":{\"type\":\"integer\"}") != null);
        } else if (std.mem.eql(u8, spec.name, "memory_versions")) {
            saw_memory_versions = true;
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"limit\":{\"type\":\"integer\"}") != null);
        } else if (std.mem.eql(u8, spec.name, "memory_search")) {
            saw_memory_search = true;
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"limit\":{\"type\":\"integer\"}") != null);
        } else if (std.mem.eql(u8, spec.name, "memory_create")) {
            saw_memory_create = true;
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"name\":{\"type\":\"string\"}") != null);
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"write_protected\":{\"type\":\"boolean\"}") != null);
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"unevictable\":{\"type\":\"boolean\"}") != null);
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"content\":{}") != null);
        } else if (std.mem.eql(u8, spec.name, "memory_mutate")) {
            saw_memory_mutate = true;
            try std.testing.expect(std.mem.indexOf(u8, spec.parameters_json, "\"content\":{}") != null);
        }
    }

    try std.testing.expect(saw_memory_load);
    try std.testing.expect(saw_memory_versions);
    try std.testing.expect(saw_memory_search);
    try std.testing.expect(saw_memory_create);
    try std.testing.expect(saw_memory_mutate);
}

test "runtime_server: invalid provider tool name returns provider_request_invalid" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    try server.runtime.world_tools.registerWorldTool(
        "bad.tool.name",
        "invalid provider tool name",
        &[_]tool_registry.ToolParam{},
        mockWorldToolOk,
    );

    const response = try server.handleMessage("{\"id\":\"req-invalid-tool-name\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"provider_request_invalid\"") != null);
}

test "runtime_server: duplicate provider tool names return provider_request_invalid" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    try server.runtime.world_tools.registerWorldTool(
        "memory_load",
        "conflicts with built-in brain tool",
        &[_]tool_registry.ToolParam{},
        mockWorldToolOk,
    );

    const response = try server.handleMessage("{\"id\":\"req-duplicate-tool-name\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"provider_request_invalid\"") != null);
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

test "runtime_server: connect returns ack while bootstrap runs separately once" {
    const allocator = std.testing.allocator;
    const server = try RuntimeServer.create(allocator, "agent-first", .{
        .ltm_directory = "",
        .ltm_filename = "",
        .default_agent_id = "agent-first",
    });
    defer server.destroy();

    const first_connect = try server.handleMessageFrames("{\"id\":\"req-connect-1\",\"type\":\"connect\"}");
    defer deinitResponseFrames(allocator, first_connect);

    try std.testing.expectEqual(@as(usize, 1), first_connect.len);
    try std.testing.expect(std.mem.indexOf(u8, first_connect[0], "\"type\":\"connect.ack\"") != null);

    const first_bootstrap = try server.handleConnectBootstrapFrames("req-connect-1");
    defer deinitResponseFrames(allocator, first_bootstrap);
    try std.testing.expectEqual(@as(usize, 1), first_bootstrap.len);
    try std.testing.expect(std.mem.indexOf(u8, first_bootstrap[0], "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, first_bootstrap[0], "System Bootstrap") != null);

    const second_bootstrap = try server.handleConnectBootstrapFrames("req-connect-2");
    defer deinitResponseFrames(allocator, second_bootstrap);
    try std.testing.expectEqual(@as(usize, 0), second_bootstrap.len);
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

test "runtime_server: provider plain text without markers is surfaced to user" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelPlainTextNoMarkers;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-fallback\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"content\":\"ok\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, response, "plain text without task markers") != null);

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "plain text without task markers") != null);
}

test "runtime_server: provider unicode plain text is surfaced instead of fallback ok" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelPlainTextUnicode;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-unicode\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"content\":\"ok\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Hello! 👋") != null);
}

test "runtime_server: provider request snapshot is refreshed before send" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamAssertsFreshActiveSnapshot;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    var stale = try server.runtime.active_memory.createActiveNoHistory(
        "primary",
        "core.stale_provider_entry",
        "core.system_prompt",
        "\"stale\"",
        true,
        true,
    );
    defer stale.deinit(allocator);

    const response = try server.handleMessage("{\"id\":\"req-provider-fresh-snapshot\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "fresh snapshot response") != null);
}

test "runtime_server: provider-backed session.send emits debug.event frames when enabled" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModel;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-debug", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const without_debug = try server.handleMessageFrames("{\"id\":\"req-debug-off\",\"type\":\"session.send\",\"content\":\"hello\"}");
    defer deinitResponseFrames(allocator, without_debug);
    for (without_debug) |payload| {
        try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"debug.event\"") == null);
    }

    const with_debug = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-debug-on\",\"type\":\"session.send\",\"content\":\"hello\"}",
        true,
    );
    defer deinitResponseFrames(allocator, with_debug);

    var saw_provider_request = false;
    var saw_provider_response = false;
    var saw_session_receive = false;
    for (with_debug) |payload| {
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.request\"") != null) {
            saw_provider_request = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"api_key\":\"[redacted]\"") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.response\"") != null) {
            saw_provider_response = true;
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"session.receive\"") != null) {
            saw_session_receive = true;
        }
    }

    try std.testing.expect(saw_provider_request);
    try std.testing.expect(saw_provider_response);
    try std.testing.expect(saw_session_receive);
}

test "runtime_server: debug provider.tool_call frames redact nested tool arguments" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithSensitiveToolLoop;
    mockSensitiveToolLoopCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-debug-sensitive", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-debug-sensitive\",\"type\":\"session.send\",\"content\":\"use tool\"}",
        true,
    );
    defer deinitResponseFrames(allocator, responses);

    var saw_tool_call_debug = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.tool_call\"") != null) {
            saw_tool_call_debug = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"arguments\":") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"api_key\":\"[redacted]\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "sensitive-key") == null);
        }
    }

    try std.testing.expect(saw_tool_call_debug);
}

test "runtime_server: debug stream includes runtime.tool_result frames for executed tools" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonToolEnvelope;
    mockJsonToolEnvelopeCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-debug-tool-results", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-debug-tool-results\",\"type\":\"session.send\",\"content\":\"use tool\"}",
        true,
    );
    defer deinitResponseFrames(allocator, responses);

    var saw_tool_result_debug = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"category\":\"runtime.tool_result\"") != null) {
            saw_tool_result_debug = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"has_error\":false") != null);
        }
    }

    try std.testing.expect(saw_tool_result_debug);
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
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"name\":\"file_list\"") != null);
}

test "runtime_server: explicit json tool_calls envelope executes world tool and returns final response" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonToolEnvelope;
    mockJsonToolEnvelopeCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-json-tools\",\"type\":\"session.send\",\"content\":\"use tools\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "json tool loop complete") != null) saw_final = true;
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(saw_final);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"kind\":\"tool_result\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"tool_calls\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"name\":\"file_list\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "json-call-") != null);
}

test "runtime_server: post-tool implicit wait fallback triggers followup round" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonToolEnvelopeImplicitWait;
    mockJsonToolEnvelopeImplicitWaitCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-json-tools-followup\",\"type\":\"session.send\",\"content\":\"use tools\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    var saw_generic_ok = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "json tool loop recovered complete") != null) saw_final = true;
        if (std.mem.indexOf(u8, payload, "\"content\":\"ok\"") != null) saw_generic_ok = true;
    }

    try std.testing.expect(saw_final);
    try std.testing.expect(!saw_generic_ok);
    try std.testing.expectEqual(@as(usize, 3), mockJsonToolEnvelopeImplicitWaitCallCount);
}

test "runtime_server: pre-tool plain-text intent fallback triggers followup round" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithPlainTextIntentThenJsonTool;
    mockPlainTextIntentFollowupCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-plain-intent-followup\",\"type\":\"session.send\",\"content\":\"run tools\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "plain-text intent recovered complete") != null) saw_final = true;
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(saw_final);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"kind\":\"tool_result\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "On it. I'll execute the tool call now.") == null);
    try std.testing.expectEqual(@as(usize, 3), mockPlainTextIntentFollowupCallCount);
}

test "runtime_server: message-only JSON response triggers followup instead of task complete" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonMessageOnlyThenTaskComplete;
    mockJsonMessageOnlyFollowupCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-message-only-followup\",\"type\":\"session.send\",\"content\":\"do work\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    var saw_message_only_as_final = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "json message-only recovered complete") != null) saw_final = true;
        if (std.mem.indexOf(u8, payload, "I'll do that now.") != null) saw_message_only_as_final = true;
    }

    try std.testing.expect(saw_final);
    try std.testing.expect(!saw_message_only_as_final);
    try std.testing.expectEqual(@as(usize, 2), mockJsonMessageOnlyFollowupCallCount);
}

test "runtime_server: wait_for after tool failure triggers followup instead of stopping" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonToolEnvelopeErrorThenWait;
    mockJsonToolEnvelopeErrorWaitCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFrames("{\"id\":\"req-provider-json-tools-error-wait\",\"type\":\"session.send\",\"content\":\"use tools\"}");
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    var saw_generic_ok = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "reported tool failure") != null) saw_final = true;
        if (std.mem.indexOf(u8, payload, "\"content\":\"ok\"") != null) saw_generic_ok = true;
    }

    try std.testing.expect(saw_final);
    try std.testing.expect(!saw_generic_ok);
    try std.testing.expectEqual(@as(usize, 3), mockJsonToolEnvelopeErrorWaitCallCount);
}

test "runtime_server: multiple structured tool calls are rejected with protocol error" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonMultiToolBatch;
    mockJsonToolEnvelopeMultiToolBatchCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-provider-json-multi-batch\",\"type\":\"session.send\",\"content\":\"use tools\"}",
        true,
    );
    defer deinitResponseFrames(allocator, responses);

    var saw_final = false;
    var saw_rejected_debug = false;
    var saw_tool_call_debug = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "multi-tool batch rejected and corrected") != null) saw_final = true;
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.tool_call_rejected\"") != null) saw_rejected_debug = true;
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.tool_call\"") != null) saw_tool_call_debug = true;
    }

    const snapshot = try server.runtime.active_memory.snapshotActive(allocator, "primary");
    defer memory.deinitItems(allocator, snapshot);
    const snapshot_json = try memory.toActiveMemoryJson(allocator, "primary", snapshot);
    defer allocator.free(snapshot_json);

    try std.testing.expect(saw_final);
    try std.testing.expect(saw_rejected_debug);
    try std.testing.expect(!saw_tool_call_debug);
    try std.testing.expect(std.mem.indexOf(u8, snapshot_json, "\"invalid_tool_batch\"") != null);
}

test "runtime_server: multi-tool rejection does not exit on plain-text fallback while pending tool failure" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelWithJsonMultiToolBatchThenPlainText;
    mockJsonToolEnvelopeMultiToolBatchPlainTextCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-json-multi-batch-plain\",\"type\":\"session.send\",\"content\":\"use tools\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "recovered after plain-text fallback") != null);
    try std.testing.expectEqual(@as(usize, 3), mockJsonToolEnvelopeMultiToolBatchPlainTextCount);
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

    try std.testing.expect(std.mem.indexOf(u8, response, "\"type\":\"session.receive\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\"content\":\"ok\"") != null);

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

        try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"provider_unavailable\"") != null);
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

test "runtime_server: provider stream failures surface mapped debug details" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelStreamFailure;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-provider-stream-failure\",\"type\":\"session.send\",\"content\":\"hello provider\"}",
        true,
    );
    defer deinitResponseFrames(allocator, responses);

    var saw_provider_error_debug = false;
    var saw_runtime_error_debug = false;
    var saw_error_frame = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"category\":\"provider.error\"") != null) {
            saw_provider_error_debug = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"error\":\"CompleteErrorUnavailable\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"mapped_error\":\"ProviderStreamFailed\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"source\":\"stream_error\"") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"category\":\"runtime.error\"") != null) {
            saw_runtime_error_debug = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"error\":\"ProviderStreamFailed\"") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"error\"") != null) {
            saw_error_frame = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"code\":\"execution_failed\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "provider stream failed") != null);
        }
    }

    try std.testing.expect(saw_provider_error_debug);
    try std.testing.expect(saw_runtime_error_debug);
    try std.testing.expect(saw_error_frame);
}

test "runtime_server: classify WriteFailed as retryable provider unavailable" {
    const from_message = RuntimeServer.classifyProviderFailure(null, "Request failed with error: WriteFailed");
    try std.testing.expectEqual(RuntimeServerError.ProviderUnavailable, from_message.runtime_error);
    try std.testing.expect(from_message.retryable);

    const from_err_name = RuntimeServer.classifyProviderFailure("WriteFailed", null);
    try std.testing.expectEqual(RuntimeServerError.ProviderUnavailable, from_err_name.runtime_error);
    try std.testing.expect(from_err_name.retryable);
}

test "runtime_server: provider rate-limit failures return provider_rate_limited code" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelRateLimited;
    mockRateLimitCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-rate-limit\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"provider_rate_limited\"") != null);
    try std.testing.expect(mockRateLimitCallCount >= PROVIDER_STREAM_MAX_ATTEMPTS);
}

test "runtime_server: provider auth failures are not retried and return provider_auth_failed" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelAuthFailed;
    mockAuthFailureCallCount = 0;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-test", .{
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const response = try server.handleMessage("{\"id\":\"req-provider-auth\",\"type\":\"session.send\",\"content\":\"hello provider\"}");
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"code\":\"provider_auth_failed\"") != null);
    try std.testing.expectEqual(@as(usize, 1), mockAuthFailureCallCount);
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

test "runtime_server: runtime operation timeout emits debug timeout frame when debug enabled" {
    const allocator = std.testing.allocator;
    const original_stream_fn = streamByModelFn;
    defer streamByModelFn = original_stream_fn;
    streamByModelFn = mockProviderStreamByModelSlow;

    const server = try RuntimeServer.createWithProvider(allocator, "agent-timeout-debug", .{
        .chat_operation_timeout_ms = 10,
        .ltm_directory = "",
        .ltm_filename = "",
    }, .{
        .name = "openai",
        .model = "gpt-4o-mini",
        .api_key = "test-key",
    });
    defer server.destroy();

    const responses = try server.handleMessageFramesWithDebug(
        "{\"id\":\"req-provider-timeout-debug\",\"type\":\"session.send\",\"content\":\"hello provider\"}",
        true,
    );
    defer deinitResponseFrames(allocator, responses);

    var saw_timeout_debug = false;
    var saw_runtime_error_debug = false;
    var saw_timeout_error = false;
    for (responses) |payload| {
        if (std.mem.indexOf(u8, payload, "\"type\":\"debug.event\"") != null and
            std.mem.indexOf(u8, payload, "\"category\":\"runtime.timeout\"") != null)
        {
            saw_timeout_debug = true;
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"operation_class\":\"chat\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, payload, "\"timeout_ms\":10") != null);
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"debug.event\"") != null and
            std.mem.indexOf(u8, payload, "\"category\":\"runtime.error\"") != null and
            std.mem.indexOf(u8, payload, "RuntimeJobTimeout") != null)
        {
            saw_runtime_error_debug = true;
        }
        if (std.mem.indexOf(u8, payload, "\"type\":\"error\"") != null and
            std.mem.indexOf(u8, payload, "\"code\":\"runtime_timeout\"") != null)
        {
            saw_timeout_error = true;
        }
    }

    try std.testing.expect(saw_timeout_debug);
    try std.testing.expect(saw_runtime_error_debug);
    try std.testing.expect(saw_timeout_error);
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
