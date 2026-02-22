const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get ziggy-piai dependency
    const ziggy_piai_dep = b.dependency("ziggy_piai", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_piai_module = ziggy_piai_dep.module("ziggypiai");
    const ziggy_spider_protocol_dep = b.dependency("ziggy_spider_protocol", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_spider_protocol_module = ziggy_spider_protocol_dep.module("ziggy-spider-protocol");
    const ziggy_memory_store_dep = b.dependency("ziggy_memory_store", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_memory_store_module = ziggy_memory_store_dep.module("ziggy-memory-store");
    const ziggy_tool_runtime_dep = b.dependency("ziggy_tool_runtime", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_tool_runtime_module = ziggy_tool_runtime_dep.module("ziggy-tool-runtime");
    const ziggy_runtime_hooks_dep = b.dependency("ziggy_runtime_hooks", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_runtime_hooks_module = ziggy_runtime_hooks_dep.module("ziggy-runtime-hooks");
    const ziggy_run_orchestrator_dep = b.dependency("ziggy_run_orchestrator", .{
        .target = target,
        .optimize = optimize,
    });
    const ziggy_run_orchestrator_module = ziggy_run_orchestrator_dep.module("ziggy-run-orchestrator");

    // Spiderweb executable
    const spiderweb_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addImport("ziggy-piai", ziggy_piai_module);
    spiderweb_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    spiderweb_mod.addImport("ziggy-memory-store", ziggy_memory_store_module);
    spiderweb_mod.addImport("ziggy-tool-runtime", ziggy_tool_runtime_module);
    spiderweb_mod.addImport("ziggy-runtime-hooks", ziggy_runtime_hooks_module);
    spiderweb_mod.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);

    // Add agent_config module for flat config loading
    const agent_config_mod = b.createModule(.{
        .root_source_file = b.path("src/agent_config.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addImport("agent_config", agent_config_mod);

    const spiderweb = b.addExecutable(.{
        .name = "spiderweb",
        .root_module = spiderweb_mod,
    });
    spiderweb.linkLibC();
    spiderweb.linkSystemLibrary("sqlite3");

    b.installArtifact(spiderweb);

    // Config CLI executable
    const config_mod = b.createModule(.{
        .root_source_file = b.path("src/config_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    config_mod.addImport("ziggy-piai", ziggy_piai_module);

    const config_cli = b.addExecutable(.{
        .name = "spiderweb-config",
        .root_module = config_mod,
    });
    config_cli.linkLibC();

    b.installArtifact(config_cli);

    // Run command
    const run_cmd = b.addRunArtifact(spiderweb);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run spiderweb");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("ziggy-piai", ziggy_piai_module);
    test_mod.addImport("agent_config", agent_config_mod);
    test_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    test_mod.addImport("ziggy-memory-store", ziggy_memory_store_module);
    test_mod.addImport("ziggy-tool-runtime", ziggy_tool_runtime_module);
    test_mod.addImport("ziggy-runtime-hooks", ziggy_runtime_hooks_module);
    test_mod.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);

    const spiderweb_tests = b.addTest(.{
        .root_module = test_mod,
    });
    spiderweb_tests.linkLibC();
    spiderweb_tests.linkSystemLibrary("sqlite3");

    const run_tests = b.addRunArtifact(spiderweb_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    const hatch_test_step = b.step("test-hatch", "Deprecated: no-op step retained for compatibility");
    hatch_test_step.dependOn(&run_tests.step);
}
