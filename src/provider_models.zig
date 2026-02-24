const std = @import("std");

pub fn preferredDefaultModel(provider_name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, provider_name, "openai-codex")) return "gpt-5.3-codex";
    if (std.mem.eql(u8, provider_name, "openai-codex-spark")) return "chatgpt5.3-spark";
    return null;
}

pub fn remapLegacyModel(provider_name: []const u8, model_name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, provider_name, "openai-codex")) {
        if (std.mem.eql(u8, model_name, "gpt-5.1")) return "gpt-5.3-codex";
        if (std.mem.eql(u8, model_name, "gpt-5.1-codex")) return "gpt-5.3-codex";
    }

    if (std.mem.eql(u8, provider_name, "openai-codex-spark")) {
        if (std.mem.eql(u8, model_name, "gpt-5.1")) return "chatgpt5.3-spark";
    }

    return null;
}

test "provider_models: preferred defaults are provider-specific" {
    try std.testing.expectEqualStrings("gpt-5.3-codex", preferredDefaultModel("openai-codex").?);
    try std.testing.expectEqualStrings("chatgpt5.3-spark", preferredDefaultModel("openai-codex-spark").?);
    try std.testing.expect(preferredDefaultModel("openai") == null);
}

test "provider_models: remap legacy codex model ids" {
    try std.testing.expectEqualStrings("gpt-5.3-codex", remapLegacyModel("openai-codex", "gpt-5.1").?);
    try std.testing.expectEqualStrings("gpt-5.3-codex", remapLegacyModel("openai-codex", "gpt-5.1-codex").?);
    try std.testing.expect(remapLegacyModel("openai-codex", "gpt-5.3-codex") == null);
    try std.testing.expect(remapLegacyModel("openai", "gpt-5.1") == null);
}
