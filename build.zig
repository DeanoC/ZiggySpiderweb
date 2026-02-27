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
    const spiderweb_node_module = ziggy_spider_protocol_dep.module("spiderweb_node");
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

    // Embeddable distributed filesystem module
    const spiderweb_fs_mod = b.addModule("spiderweb_fs", .{
        .root_source_file = b.path("src/fs_lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_fs_mod.addIncludePath(b.path("src/c"));
    spiderweb_fs_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);

    // Example: embeddable filesystem service
    const embed_fs_node_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/embed_fs_node.zig"),
        .target = target,
        .optimize = optimize,
    });
    embed_fs_node_example_mod.addIncludePath(b.path("src/c"));
    embed_fs_node_example_mod.addImport("spiderweb_fs", spiderweb_fs_mod);
    const embed_fs_node_example = b.addExecutable(.{
        .name = "embed-fs-node",
        .root_module = embed_fs_node_example_mod,
    });
    embed_fs_node_example.linkLibC();
    b.installArtifact(embed_fs_node_example);
    const example_embed_step = b.step("example-embed-fs-node", "Build embedded filesystem node example");
    example_embed_step.dependOn(&embed_fs_node_example.step);
    const run_embed_example = b.addRunArtifact(embed_fs_node_example);
    if (b.args) |args| {
        run_embed_example.addArgs(args);
    }
    const run_example_embed_step = b.step("run-example-embed-fs-node", "Run embedded filesystem node example");
    run_example_embed_step.dependOn(&run_embed_example.step);

    // Example: multi-service process embedding filesystem service
    const embed_multi_service_mod = b.createModule(.{
        .root_source_file = b.path("examples/embed_multi_service_node.zig"),
        .target = target,
        .optimize = optimize,
    });
    embed_multi_service_mod.addIncludePath(b.path("src/c"));
    embed_multi_service_mod.addImport("spiderweb_fs", spiderweb_fs_mod);
    embed_multi_service_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    const websocket_transport_mod = b.createModule(.{
        .root_source_file = b.path("src/websocket_transport.zig"),
        .target = target,
        .optimize = optimize,
    });
    embed_multi_service_mod.addImport("websocket_transport", websocket_transport_mod);
    const embed_multi_service_example = b.addExecutable(.{
        .name = "embed-multi-service-node",
        .root_module = embed_multi_service_mod,
    });
    embed_multi_service_example.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    embed_multi_service_example.linkLibC();
    b.installArtifact(embed_multi_service_example);
    const example_multi_step = b.step("example-embed-multi-service-node", "Build multi-service embedded node example");
    example_multi_step.dependOn(&embed_multi_service_example.step);
    const run_multi_example = b.addRunArtifact(embed_multi_service_example);
    if (b.args) |args| {
        run_multi_example.addArgs(args);
    }
    const run_example_multi_step = b.step("run-example-embed-multi-service-node", "Run multi-service embedded node example");
    run_example_multi_step.dependOn(&run_multi_example.step);

    // Spiderweb executable
    const spiderweb_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addIncludePath(b.path("src/c"));
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
    spiderweb.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    spiderweb.linkLibC();
    spiderweb.linkSystemLibrary("sqlite3");

    b.installArtifact(spiderweb);

    // Agent runtime child executable (sandbox target)
    const agent_runtime_child_mod = b.createModule(.{
        .root_source_file = b.path("src/agent_runtime_child_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    agent_runtime_child_mod.addIncludePath(b.path("src/c"));
    agent_runtime_child_mod.addImport("ziggy-piai", ziggy_piai_module);
    agent_runtime_child_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    agent_runtime_child_mod.addImport("ziggy-memory-store", ziggy_memory_store_module);
    agent_runtime_child_mod.addImport("ziggy-tool-runtime", ziggy_tool_runtime_module);
    agent_runtime_child_mod.addImport("ziggy-runtime-hooks", ziggy_runtime_hooks_module);
    agent_runtime_child_mod.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);
    agent_runtime_child_mod.addImport("agent_config", agent_config_mod);

    const spiderweb_agent_runtime = b.addExecutable(.{
        .name = "spiderweb-agent-runtime",
        .root_module = agent_runtime_child_mod,
    });
    spiderweb_agent_runtime.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    spiderweb_agent_runtime.linkLibC();
    spiderweb_agent_runtime.linkSystemLibrary("sqlite3");
    b.installArtifact(spiderweb_agent_runtime);

    // Distributed filesystem node executable
    const fs_node_mod = b.createModule(.{
        .root_source_file = b.path("src/fs_node_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fs_node_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    const spiderweb_fs_node = b.addExecutable(.{
        .name = "spiderweb-fs-node",
        .root_module = fs_node_mod,
    });
    spiderweb_fs_node.linkLibC();
    b.installArtifact(spiderweb_fs_node);

    // Distributed filesystem mount/router executable
    const fs_mount_mod = b.createModule(.{
        .root_source_file = b.path("src/fs_mount_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fs_mount_mod.addIncludePath(b.path("src/c"));
    fs_mount_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    const spiderweb_fs_mount = b.addExecutable(.{
        .name = "spiderweb-fs-mount",
        .root_module = fs_mount_mod,
    });
    spiderweb_fs_mount.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    spiderweb_fs_mount.linkLibC();
    b.installArtifact(spiderweb_fs_mount);

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

    // Control-plane CLI executable
    const control_mod = b.createModule(.{
        .root_source_file = b.path("src/control_cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    const control_cli = b.addExecutable(.{
        .name = "spiderweb-control",
        .root_module = control_mod,
    });
    control_cli.linkLibC();

    b.installArtifact(control_cli);

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
    test_mod.addIncludePath(b.path("src/c"));
    test_mod.addImport("ziggy-piai", ziggy_piai_module);
    test_mod.addImport("agent_config", agent_config_mod);
    test_mod.addImport("ziggy-spider-protocol", ziggy_spider_protocol_module);
    test_mod.addImport("spiderweb_node", spiderweb_node_module);
    test_mod.addImport("ziggy-memory-store", ziggy_memory_store_module);
    test_mod.addImport("ziggy-tool-runtime", ziggy_tool_runtime_module);
    test_mod.addImport("ziggy-runtime-hooks", ziggy_runtime_hooks_module);
    test_mod.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);

    const spiderweb_tests = b.addTest(.{
        .root_module = test_mod,
    });
    spiderweb_tests.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    spiderweb_tests.linkLibC();
    spiderweb_tests.linkSystemLibrary("sqlite3");

    const run_tests = b.addRunArtifact(spiderweb_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    const hatch_test_step = b.step("test-hatch", "Deprecated: no-op step retained for compatibility");
    hatch_test_step.dependOn(&run_tests.step);
}
