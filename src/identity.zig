const std = @import("std");

const Layer = struct { name: []const u8, filename: []const u8 };
const HeadingRecord = struct { key: []const u8, source_layer: []const u8 };

const PREAMBLE_KEY = "__preamble__";
const MAX_IDENTITY_FILE_BYTES = 1024 * 1024;
const FALLBACK_PROMPT = "You are a helpful AI assistant.";

const LAYERS = [_]Layer{
    .{ .name = "SOUL", .filename = "SOUL.md" },
    .{ .name = "AGENT", .filename = "AGENT.md" },
    .{ .name = "IDENTITY", .filename = "IDENTITY.md" },
    .{ .name = "USER", .filename = "USER.md" },
};

pub fn loadMergedPrompt(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    agent_id: []const u8,
) ![]u8 {
    var merged_prompt = std.ArrayListUnmanaged(u8){};
    var used_headings = std.ArrayListUnmanaged(HeadingRecord){};
    errdefer {
        merged_prompt.deinit(allocator);
        used_headings.deinit(allocator);
    }

    const layers = &LAYERS;
    var loaded_any = false;
    for (layers) |layer| {
        const layer_content = try loadLayerContent(allocator, base_dir, agent_id, layer.filename);
        if (layer_content) |content| {
            loaded_any = true;
            try processLayer(allocator, layer.name, content, &used_headings, &merged_prompt);
            allocator.free(content);
        } else {
            std.log.warn("Identity layer missing for agent={s}: {s}", .{ agent_id, layer.filename });
        }
    }

    if (!loaded_any or merged_prompt.items.len == 0) {
        return try allocator.dupe(u8, FALLBACK_PROMPT);
    }

    return merged_prompt.toOwnedSlice(allocator);
}

fn loadLayerContent(
    allocator: std.mem.Allocator,
    base_dir: []const u8,
    agent_id: []const u8,
    filename: []const u8,
) !?[]u8 {
    const agents_dir = "agents"; // Default if not in runtime
    const candidate1 = try std.fs.path.join(allocator, &.{ base_dir, agents_dir, agent_id, filename });
    defer allocator.free(candidate1);
    if (try readFileIfExists(allocator, candidate1)) |content| return content;

    const candidate2 = try std.fs.path.join(allocator, &.{ base_dir, agent_id, filename });
    defer allocator.free(candidate2);
    if (try readFileIfExists(allocator, candidate2)) |content| return content;

    const candidate3 = try std.fs.path.join(allocator, &.{ base_dir, filename });
    defer allocator.free(candidate3);
    return try readFileIfExists(allocator, candidate3);
}

fn readFileIfExists(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer file.close();

    return try file.readToEndAlloc(allocator, MAX_IDENTITY_FILE_BYTES);
}

fn processLayer(
    allocator: std.mem.Allocator,
    layer_name: []const u8,
    layer_content: []const u8,
    used_headings: *std.ArrayListUnmanaged(HeadingRecord),
    merged_prompt: *std.ArrayListUnmanaged(u8),
) !void {
    var lines = std.mem.splitSequence(u8, layer_content, "\n");
    var current_heading_key: ?[]const u8 = null;
    var current_heading_raw: ?[]const u8 = null;
    var section_body = std.ArrayListUnmanaged(u8){};
    defer section_body.deinit(allocator);

    while (lines.next()) |line| {
        if (isHeadingLine(line)) |heading| {
            if (section_body.items.len > 0 or current_heading_raw != null) {
                try appendSection(
                    allocator,
                    layer_name,
                    current_heading_raw,
                    current_heading_key,
                    section_body.items,
                    used_headings,
                    merged_prompt,
                );
            }
            section_body.clearRetainingCapacity();
            current_heading_key = heading.key;
            current_heading_raw = heading.raw;
        } else {
            try section_body.appendSlice(allocator, line);
            try section_body.append(allocator, '\n');
        }
    }

    if (section_body.items.len > 0 or current_heading_raw != null) {
        try appendSection(
            allocator,
            layer_name,
            current_heading_raw,
            current_heading_key,
            section_body.items,
            used_headings,
            merged_prompt,
        );
    }
}

const Heading = struct { raw: []const u8, key: []const u8 };

fn isHeadingLine(line: []const u8) ?Heading {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return null;
    if (trimmed[0] != '#') return null;

    var idx: usize = 0;
    while (idx < trimmed.len and trimmed[idx] == '#') idx += 1;
    if (idx == 0) return null;

    const heading_key = if (idx < trimmed.len)
        std.mem.trim(u8, trimmed[idx..], " \t")
    else
        "";

    if (heading_key.len == 0) return null;
    return .{ .raw = trimmed, .key = heading_key };
}

fn appendSection(
    allocator: std.mem.Allocator,
    layer_name: []const u8,
    heading_raw: ?[]const u8,
    heading_key: ?[]const u8,
    section_body: []const u8,
    used_headings: *std.ArrayListUnmanaged(HeadingRecord),
    merged_prompt: *std.ArrayListUnmanaged(u8),
) !void {
    if (section_body.len == 0 or !hasNonWhitespace(section_body)) return;

    const effective_key = heading_key orelse PREAMBLE_KEY;
    if (findConflict(used_headings, effective_key)) |existing| {
        const conflict = if (heading_key) |heading| heading else PREAMBLE_KEY;
        std.log.warn("Identity section conflict: layer={s} heading=\"{s}\" shadowed by {s}", .{
            layer_name,
            conflict,
            existing.source_layer,
        });
        return;
    }

    if (merged_prompt.items.len > 0) {
        try merged_prompt.append(allocator, '\n');
        try merged_prompt.append(allocator, '\n');
    }
    if (heading_raw) |raw| {
        try merged_prompt.appendSlice(allocator, raw);
        try merged_prompt.append(allocator, '\n');
    }
    try merged_prompt.appendSlice(allocator, section_body);

    try used_headings.append(allocator, .{
        .key = try allocator.dupe(u8, effective_key),
        .source_layer = layer_name,
    });
}

fn findConflict(
    used_headings: *std.ArrayListUnmanaged(HeadingRecord),
    candidate_key: []const u8,
) ?HeadingRecord {
    for (used_headings.items) |record| {
        if (std.ascii.eqlIgnoreCase(record.key, candidate_key)) {
            return record;
        }
    }
    return null;
}

fn hasNonWhitespace(value: []const u8) bool {
    for (value) |c| {
        if (!std.ascii.isWhitespace(c)) return true;
    }
    return false;
}

test "identity: loadMergedPrompt applies precedence to headings" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const dir_name = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir_name);
    const agent_name = "agent-a";

    const agent_path = try std.fmt.allocPrint(allocator, "{s}/agents/{s}", .{ dir_name, agent_name });
    defer allocator.free(agent_path);
    try std.fs.cwd().makePath(agent_path);

    const soul_path = try std.fmt.allocPrint(allocator, "{s}/SOUL.md", .{agent_path});
    defer allocator.free(soul_path);
    const agent_path_file = try std.fmt.allocPrint(allocator, "{s}/AGENT.md", .{agent_path});
    defer allocator.free(agent_path_file);
    const user_path = try std.fmt.allocPrint(allocator, "{s}/USER.md", .{agent_path});
    defer allocator.free(user_path);

    try writeFile(soul_path, "# Style\nHigh-priority\n# Purpose\nSolve with certainty\n");
    try writeFile(agent_path_file, "# Style\nAgent overrides\n# Rules\nDo not override\n");
    try writeFile(user_path, "# User\nPrefer concise updates\n");

    const merged = try loadMergedPrompt(allocator, dir_name, agent_name);
    defer allocator.free(merged);

    try std.testing.expect(std.mem.indexOf(u8, merged, "High-priority") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "Agent overrides") == null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "Solve with certainty") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "Do not override") != null);
    try std.testing.expect(std.mem.indexOf(u8, merged, "Prefer concise updates") != null);
}

test "identity: fallback to default prompt when no files present" {
    const allocator = std.testing.allocator;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const dir_name = try tmp_dir.dir.realpathAlloc(allocator, ".");
    defer allocator.free(dir_name);

    const prompt = try loadMergedPrompt(allocator, dir_name, "agent-none");
    defer allocator.free(prompt);

    try std.testing.expectEqualStrings(FALLBACK_PROMPT, prompt);
}

fn writeFile(path: []const u8, content: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    try file.writeAll(content);
}
