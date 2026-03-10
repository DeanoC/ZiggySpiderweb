const std = @import("std");
const unified = @import("spider-protocol").unified;
const agent_config = @import("../agents/agent_config.zig");

pub const Op = enum {
    list,
    upsert,
    delete,
};

pub fn seedNamespace(self: anytype, sub_brains_dir: u32) !void {
    return seedNamespaceAt(self, sub_brains_dir, "/global/sub_brains");
}

pub fn seedNamespaceAt(self: anytype, sub_brains_dir: u32, base_path: []const u8) !void {
    const can_manage_sub_brains = self.canManageSubBrains();
    const caps_json = if (can_manage_sub_brains)
        "{\"invoke\":true,\"operations\":[\"sub_brains_list\",\"sub_brains_upsert\",\"sub_brains_delete\"],\"discoverable\":true,\"config_mutation\":true,\"manage_allowed\":true}"
    else
        "{\"invoke\":true,\"operations\":[\"sub_brains_list\"],\"discoverable\":true,\"config_mutation\":false,\"manage_allowed\":false}";
    const escaped_base_path = try unified.jsonEscape(self.allocator, base_path);
    defer self.allocator.free(escaped_base_path);
    const shape_json = try std.fmt.allocPrint(
        self.allocator,
        "{{\"kind\":\"venom\",\"venom_id\":\"sub_brains\",\"shape\":\"{s}/{{README.md,SCHEMA.json,CAPS.json,OPS.json,PERMISSIONS.json,STATUS.json,status.json,result.json,control/*}}\"}}",
        .{escaped_base_path},
    );
    defer self.allocator.free(shape_json);
    try self.addDirectoryDescriptors(
        sub_brains_dir,
        "Sub-Brains",
        shape_json,
        caps_json,
        "Manage sub-brain configuration for this agent through Acheron control files.",
    );
    _ = try self.addFile(
        sub_brains_dir,
        "OPS.json",
        "{\"model\":\"local_bridge\",\"invoke\":\"control/invoke.json\",\"transport\":\"acheron-local\",\"paths\":{\"list\":\"control/list.json\",\"upsert\":\"control/upsert.json\",\"delete\":\"control/delete.json\"},\"operations\":{\"list\":\"sub_brains_list\",\"upsert\":\"sub_brains_upsert\",\"delete\":\"sub_brains_delete\"}}",
        false,
        .none,
    );
    _ = try self.addFile(
        sub_brains_dir,
        "RUNTIME.json",
        "{\"type\":\"acheron_local\",\"component\":\"acheron_session\",\"subject\":\"agent_sub_brains\"}",
        false,
        .none,
    );
    _ = try self.addFile(
        sub_brains_dir,
        "PERMISSIONS.json",
        "{\"default\":\"allow-by-default\",\"allow_roles\":[\"admin\",\"user\"],\"scope\":\"agent\",\"project_token_required\":false}",
        false,
        .none,
    );
    _ = try self.addFile(
        sub_brains_dir,
        "STATUS.json",
        "{\"venom_id\":\"sub_brains\",\"state\":\"namespace\",\"has_invoke\":true}",
        false,
        .none,
    );
    self.sub_brains_status_id = try self.addFile(
        sub_brains_dir,
        "status.json",
        "{\"state\":\"idle\",\"tool\":null,\"updated_at_ms\":0,\"error\":null}",
        false,
        .none,
    );
    const initial_result = try buildListResultJson(self);
    defer self.allocator.free(initial_result);
    self.sub_brains_result_id = try self.addFile(
        sub_brains_dir,
        "result.json",
        initial_result,
        false,
        .none,
    );

    const control_dir = try self.addDir(sub_brains_dir, "control", false);
    _ = try self.addFile(
        control_dir,
        "README.md",
        "Use list/upsert/delete operation files, or invoke.json with op=list|upsert|delete plus arguments. Upsert/delete require sub-brain management capability.\n",
        false,
        .none,
    );
    _ = try self.addFile(control_dir, "invoke.json", "", true, .sub_brains_invoke);
    _ = try self.addFile(control_dir, "list.json", "", true, .sub_brains_list);
    _ = try self.addFile(control_dir, "upsert.json", "", can_manage_sub_brains, .sub_brains_upsert);
    _ = try self.addFile(control_dir, "delete.json", "", can_manage_sub_brains, .sub_brains_delete);
}

pub fn handleInvokeWrite(self: anytype, invoke_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(invoke_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    const obj = parsed.value.object;

    const op_raw = blk: {
        if (obj.get("op")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("operation")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("tool")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        if (obj.get("tool_name")) |value| if (value == .string and value.string.len > 0) break :blk value.string;
        break :blk null;
    } orelse return error.InvalidPayload;
    const op = parseOp(op_raw) orelse return error.InvalidPayload;

    const args_obj = blk: {
        if (obj.get("arguments")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        if (obj.get("args")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        break :blk obj;
    };
    return executeOp(self, op, args_obj, raw_input.len);
}

pub fn handleListWrite(self: anytype, list_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    const payload = if (input.len == 0) "{}" else input;
    try self.setFileContent(list_node_id, payload);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeOp(self, .list, parsed.value.object, raw_input.len);
}

pub fn handleUpsertWrite(self: anytype, upsert_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(upsert_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeOp(self, .upsert, parsed.value.object, raw_input.len);
}

pub fn handleDeleteWrite(self: anytype, delete_node_id: u32, raw_input: []const u8) !usize {
    const input = std.mem.trim(u8, raw_input, " \t\r\n");
    if (input.len == 0) return error.InvalidPayload;
    try self.setFileContent(delete_node_id, input);

    var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, input, .{}) catch return error.InvalidPayload;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidPayload;
    return executeOp(self, .delete, parsed.value.object, raw_input.len);
}

pub fn parseOp(raw: []const u8) ?Op {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (std.mem.eql(u8, value, "list") or std.mem.eql(u8, value, "sub_brains_list")) return .list;
    if (std.mem.eql(u8, value, "upsert") or std.mem.eql(u8, value, "sub_brains_upsert")) return .upsert;
    if (std.mem.eql(u8, value, "delete") or std.mem.eql(u8, value, "sub_brains_delete")) return .delete;
    return null;
}

pub fn operationName(op: Op) []const u8 {
    return switch (op) {
        .list => "list",
        .upsert => "upsert",
        .delete => "delete",
    };
}

pub fn statusToolName(op: Op) []const u8 {
    return switch (op) {
        .list => "sub_brains_list",
        .upsert => "sub_brains_upsert",
        .delete => "sub_brains_delete",
    };
}

fn executeOp(self: anytype, op: Op, args_obj: std.json.ObjectMap, written: usize) !usize {
    const tool_name = statusToolName(op);
    const running_status = try self.buildServiceInvokeStatusJson("running", tool_name, null);
    defer self.allocator.free(running_status);
    if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, running_status);

    const result_payload = executeOpPayload(self, op, args_obj) catch |err| {
        const error_message = @errorName(err);
        const error_code = switch (err) {
            error.AccessDenied => "forbidden",
            else => "invalid_payload",
        };
        const failed_status = try self.buildServiceInvokeStatusJson("failed", tool_name, error_message);
        defer self.allocator.free(failed_status);
        if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, failed_status);
        const failed_result = try buildFailureResultJson(self, op, error_code, error_message);
        defer self.allocator.free(failed_result);
        if (self.sub_brains_result_id != 0) try self.setFileContent(self.sub_brains_result_id, failed_result);
        return err;
    };
    defer self.allocator.free(result_payload);

    const done_status = try self.buildServiceInvokeStatusJson("done", tool_name, null);
    defer self.allocator.free(done_status);
    if (self.sub_brains_status_id != 0) try self.setFileContent(self.sub_brains_status_id, done_status);
    if (self.sub_brains_result_id != 0) try self.setFileContent(self.sub_brains_result_id, result_payload);
    return written;
}

fn executeOpPayload(self: anytype, op: Op, args_obj: std.json.ObjectMap) ![]u8 {
    return switch (op) {
        .list => executeListOp(self),
        .upsert => executeUpsertOp(self, args_obj),
        .delete => executeDeleteOp(self, args_obj),
    };
}

fn executeListOp(self: anytype) ![]u8 {
    var config = try loadOrInitSelfAgentConfig(self);
    defer config.deinit();
    const inventory = try buildInventoryJson(self, &config);
    defer self.allocator.free(inventory);
    return buildSuccessResultJson(self, .list, inventory);
}

fn executeUpsertOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    if (!self.canManageSubBrains()) return error.AccessDenied;
    const brain_name = extractSubBrainName(args_obj) orelse return error.InvalidPayload;
    if (std.mem.eql(u8, brain_name, "primary")) return error.InvalidPayload;

    const config_obj = blk: {
        if (args_obj.get("config")) |value| {
            if (value != .object) return error.InvalidPayload;
            break :blk value.object;
        }
        break :blk args_obj;
    };

    var new_sub = try parseSubBrainConfigFromObject(self, config_obj);
    var new_sub_owned = true;
    errdefer if (new_sub_owned) new_sub.deinit(self.allocator);

    var config = try loadOrInitSelfAgentConfig(self);
    defer config.deinit();

    if (config.sub_brains.getPtr(brain_name)) |existing| {
        existing.deinit(self.allocator);
        existing.* = new_sub;
        new_sub_owned = false;
    } else {
        const key = try self.allocator.dupe(u8, brain_name);
        errdefer self.allocator.free(key);
        try config.sub_brains.put(self.allocator, key, new_sub);
        new_sub_owned = false;
    }

    try std.fs.cwd().makePath(self.agents_dir);
    try agent_config.saveAgentConfig(self.allocator, self.agents_dir, self.agent_id, &config);

    const inventory = try buildInventoryJson(self, &config);
    defer self.allocator.free(inventory);
    const escaped_brain = try unified.jsonEscape(self.allocator, brain_name);
    defer self.allocator.free(escaped_brain);
    const detail = try std.fmt.allocPrint(
        self.allocator,
        "{{\"brain_name\":\"{s}\",\"updated\":true,\"inventory\":{s}}}",
        .{ escaped_brain, inventory },
    );
    defer self.allocator.free(detail);
    return buildSuccessResultJson(self, .upsert, detail);
}

fn executeDeleteOp(self: anytype, args_obj: std.json.ObjectMap) ![]u8 {
    if (!self.canManageSubBrains()) return error.AccessDenied;
    const brain_name = extractSubBrainName(args_obj) orelse return error.InvalidPayload;
    if (std.mem.eql(u8, brain_name, "primary")) return error.InvalidPayload;

    var config = try loadOrInitSelfAgentConfig(self);
    defer config.deinit();

    var removed = false;
    if (config.sub_brains.fetchRemove(brain_name)) |entry| {
        self.allocator.free(entry.key);
        var value = entry.value;
        value.deinit(self.allocator);
        removed = true;
    }

    try std.fs.cwd().makePath(self.agents_dir);
    try agent_config.saveAgentConfig(self.allocator, self.agents_dir, self.agent_id, &config);

    const inventory = try buildInventoryJson(self, &config);
    defer self.allocator.free(inventory);
    const escaped_brain = try unified.jsonEscape(self.allocator, brain_name);
    defer self.allocator.free(escaped_brain);
    const detail = try std.fmt.allocPrint(
        self.allocator,
        "{{\"brain_name\":\"{s}\",\"removed\":{},\"inventory\":{s}}}",
        .{ escaped_brain, removed, inventory },
    );
    defer self.allocator.free(detail);
    return buildSuccessResultJson(self, .delete, detail);
}

fn loadOrInitSelfAgentConfig(self: anytype) !agent_config.AgentConfig {
    if (try agent_config.loadAgentConfigFromDir(self.allocator, self.agents_dir, self.agent_id)) |config| {
        return config;
    }
    var config = agent_config.AgentConfig.init(self.allocator);
    config.agent_id = try self.allocator.dupe(u8, self.agent_id);
    return config;
}

fn parseSubBrainConfigFromObject(self: anytype, obj: std.json.ObjectMap) !agent_config.SubBrainConfig {
    var out = agent_config.SubBrainConfig.init(self.allocator);
    errdefer out.deinit(self.allocator);

    if (obj.get("template")) |value| {
        if (value == .string) out.base.template = try self.allocator.dupe(u8, value.string) else if (value != .null) return error.InvalidPayload;
    }
    if (obj.get("provider")) |value| {
        switch (value) {
            .string => {
                out.base.provider.name = try self.allocator.dupe(u8, value.string);
            },
            .object => {
                if (value.object.get("name")) |field| {
                    if (field == .string) out.base.provider.name = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("model")) |field| {
                    if (field == .string) out.base.provider.model = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                }
                if (value.object.get("think_level")) |field| {
                    if (field == .string) out.base.provider.think_level = try self.allocator.dupe(u8, field.string) else if (field != .null) return error.InvalidPayload;
                }
            },
            .null => {},
            else => return error.InvalidPayload,
        }
    }
    if (obj.get("can_spawn_subbrains")) |value| {
        if (value == .bool) out.base.can_spawn_subbrains = value.bool else if (value != .null) return error.InvalidPayload;
    }

    try copyStringArrayConfigField(self, obj, "allowed_tools", &(out.base.allowed_tools));
    try copyStringArrayConfigField(self, obj, "denied_tools", &(out.base.denied_tools));
    try copyStringArrayConfigField(self, obj, "capabilities", &(out.base.capabilities));
    try copyRomOverridesConfigField(self, obj, "rom_overrides", &(out.base.rom_overrides));

    if (obj.get("personality")) |value| {
        if (value == .object) {
            if (value.object.get("name")) |field| {
                if (field == .string) try setBrainRomOverride(self, &(out.base), "system:personality_name", field.string) else if (field != .null) return error.InvalidPayload;
            }
            if (value.object.get("description")) |field| {
                if (field == .string) try setBrainRomOverride(self, &(out.base), "system:personality_description", field.string) else if (field != .null) return error.InvalidPayload;
            }
            if (value.object.get("creature")) |field| {
                if (field == .string) try setBrainRomOverride(self, &(out.base), "system:personality_creature", field.string) else if (field != .null) return error.InvalidPayload;
            }
            if (value.object.get("vibe")) |field| {
                if (field == .string) try setBrainRomOverride(self, &(out.base), "system:personality_vibe", field.string) else if (field != .null) return error.InvalidPayload;
            }
            if (value.object.get("emoji")) |field| {
                if (field == .string) try setBrainRomOverride(self, &(out.base), "system:personality_emoji", field.string) else if (field != .null) return error.InvalidPayload;
            }
        } else if (value != .null) {
            return error.InvalidPayload;
        }
    }
    if (obj.get("creature")) |value| {
        if (value == .string) try setBrainRomOverride(self, &(out.base), "system:personality_creature", value.string) else if (value != .null) return error.InvalidPayload;
    }
    if (obj.get("vibe")) |value| {
        if (value == .string) try setBrainRomOverride(self, &(out.base), "system:personality_vibe", value.string) else if (value != .null) return error.InvalidPayload;
    }
    if (obj.get("emoji")) |value| {
        if (value == .string) try setBrainRomOverride(self, &(out.base), "system:personality_emoji", value.string) else if (value != .null) return error.InvalidPayload;
    }

    return out;
}

fn copyStringArrayConfigField(
    self: anytype,
    obj: std.json.ObjectMap,
    field_name: []const u8,
    target: *?std.ArrayListUnmanaged([]u8),
) !void {
    const value = obj.get(field_name) orelse return;
    if (value == .null) return;
    if (value != .array) return error.InvalidPayload;
    target.* = .{};
    for (value.array.items) |entry| {
        if (entry != .string) return error.InvalidPayload;
        try target.*.?.append(self.allocator, try self.allocator.dupe(u8, entry.string));
    }
}

fn copyRomOverridesConfigField(
    self: anytype,
    obj: std.json.ObjectMap,
    field_name: []const u8,
    target: *?std.ArrayListUnmanaged(agent_config.RomEntry),
) !void {
    const value = obj.get(field_name) orelse return;
    if (value == .null) return;
    if (value != .array) return error.InvalidPayload;
    target.* = .{};
    for (value.array.items) |entry| {
        if (entry != .object) return error.InvalidPayload;
        const key = entry.object.get("key") orelse return error.InvalidPayload;
        const val = entry.object.get("value") orelse return error.InvalidPayload;
        if (key != .string or val != .string) return error.InvalidPayload;
        try target.*.?.append(self.allocator, .{
            .key = try self.allocator.dupe(u8, key.string),
            .value = try self.allocator.dupe(u8, val.string),
        });
    }
}

fn setBrainRomOverride(
    self: anytype,
    cfg: *agent_config.BrainConfig,
    key: []const u8,
    value: []const u8,
) !void {
    if (cfg.rom_overrides == null) cfg.rom_overrides = .{};
    for (cfg.rom_overrides.?.items) |*entry| {
        if (!std.mem.eql(u8, entry.key, key)) continue;
        self.allocator.free(entry.value);
        entry.value = try self.allocator.dupe(u8, value);
        return;
    }
    try cfg.rom_overrides.?.append(self.allocator, .{
        .key = try self.allocator.dupe(u8, key),
        .value = try self.allocator.dupe(u8, value),
    });
}

fn buildInventoryJson(self: anytype, config: *const agent_config.AgentConfig) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(self.allocator);
    const writer = out.writer(self.allocator);

    try writer.writeAll("{\"sub_brains\":[");
    var names = std.ArrayListUnmanaged([]const u8){};
    defer names.deinit(self.allocator);
    var it = config.sub_brains.iterator();
    while (it.next()) |entry| try names.append(self.allocator, entry.key_ptr.*);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    for (names.items, 0..) |name, idx| {
        if (idx > 0) try writer.writeByte(',');
        const sub = config.sub_brains.get(name) orelse continue;
        try writer.writeByte('{');
        try writer.writeAll("\"brain_name\":");
        try writeJsonString(writer, name);
        try writer.writeAll(",\"template\":");
        if (sub.base.template) |value| {
            try writeJsonString(writer, value);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"can_spawn_subbrains\":");
        try writer.print("{}", .{sub.base.can_spawn_subbrains});
        try writer.writeAll(",\"provider\":{");
        var provider_first = true;
        if (sub.base.provider.name) |value| {
            if (!provider_first) try writer.writeByte(',');
            provider_first = false;
            try writer.writeAll("\"name\":");
            try writeJsonString(writer, value);
        }
        if (sub.base.provider.model) |value| {
            if (!provider_first) try writer.writeByte(',');
            provider_first = false;
            try writer.writeAll("\"model\":");
            try writeJsonString(writer, value);
        }
        if (sub.base.provider.think_level) |value| {
            if (!provider_first) try writer.writeByte(',');
            provider_first = false;
            try writer.writeAll("\"think_level\":");
            try writeJsonString(writer, value);
        }
        try writer.writeByte('}');
        try writer.writeByte('}');
    }

    try writer.print("],\"count\":{d}}}", .{names.items.len});
    return out.toOwnedSlice(self.allocator);
}

fn buildSuccessResultJson(self: anytype, op: Op, result_json: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":true,\"operation\":\"{s}\",\"result\":{s},\"error\":null}}",
        .{ escaped_operation, result_json },
    );
}

fn buildFailureResultJson(self: anytype, op: Op, code: []const u8, message: []const u8) ![]u8 {
    const escaped_operation = try unified.jsonEscape(self.allocator, operationName(op));
    defer self.allocator.free(escaped_operation);
    const escaped_code = try unified.jsonEscape(self.allocator, code);
    defer self.allocator.free(escaped_code);
    const escaped_message = try unified.jsonEscape(self.allocator, message);
    defer self.allocator.free(escaped_message);
    return std.fmt.allocPrint(
        self.allocator,
        "{{\"ok\":false,\"operation\":\"{s}\",\"result\":null,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ escaped_operation, escaped_code, escaped_message },
    );
}

fn buildListResultJson(self: anytype) ![]u8 {
    var config = try loadOrInitSelfAgentConfig(self);
    defer config.deinit();
    const inventory = try buildInventoryJson(self, &config);
    defer self.allocator.free(inventory);
    return buildSuccessResultJson(self, .list, inventory);
}

fn extractSubBrainName(obj: std.json.ObjectMap) ?[]const u8 {
    const candidates = [_][]const u8{ "brain_name", "name", "brain_id", "id", "sub_brain", "sub_brain_id" };
    inline for (candidates) |field| {
        if (obj.get(field)) |value| {
            if (value == .string and value.string.len > 0) return value.string;
        }
    }
    return null;
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.print("{f}", .{std.json.fmt(value, .{})});
}
