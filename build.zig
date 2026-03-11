const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sqlite_lib_dir = b.option([]const u8, "sqlite-lib-dir", "Directory containing sqlite3 import library and runtime DLL");

    const spider_protocol_dep = b.dependency("spider_protocol", .{
        .target = target,
        .optimize = optimize,
    });
    const spider_protocol_protocol_module = b.createModule(.{
        .root_source_file = b.path("deps/spider-protocol/src/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });
    const spider_protocol_unified_module = b.createModule(.{
        .root_source_file = b.path("deps/spider-protocol/src/unified.zig"),
        .target = target,
        .optimize = optimize,
    });
    const spider_protocol_module = b.createModule(.{
        .root_source_file = b.path("src/build_support/spider_protocol_host.zig"),
        .target = target,
        .optimize = optimize,
    });
    spider_protocol_module.addImport("spider-protocol-protocol", spider_protocol_protocol_module);
    spider_protocol_module.addImport("spider-protocol-unified", spider_protocol_unified_module);
    const spiderweb_node_module = spider_protocol_dep.module("spiderweb_node");
    const spiderweb_fs_protocol_module = spider_protocol_dep.module("spiderweb_fs");
    spiderweb_node_module.addImport("spider-protocol", spider_protocol_module);
    spiderweb_fs_protocol_module.addImport("spider-protocol", spider_protocol_module);
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
    const ziggy_run_orchestrator_module = b.createModule(.{
        .root_source_file = b.path("deps/ziggy-run-orchestrator/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    ziggy_run_orchestrator_module.addImport("ziggy-memory-store", ziggy_memory_store_module);

    const ziggy_runtime_hooks_module = b.createModule(.{
        .root_source_file = b.path("deps/ziggy-runtime-hooks/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    ziggy_runtime_hooks_module.addImport("ziggy-memory-store", ziggy_memory_store_module);
    ziggy_runtime_hooks_module.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);

    const acheron_fs_client_mod = b.createModule(.{
        .root_source_file = b.path("src/acheron/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    acheron_fs_client_mod.addImport("spider-protocol", spider_protocol_module);
    const spiderweb_fs_cache_mod = b.createModule(.{
        .root_source_file = b.path("src/venoms/fs/fs_cache.zig"),
        .target = target,
        .optimize = optimize,
    });
    const spiderweb_fs_source_policy_mod = b.createModule(.{
        .root_source_file = b.path("src/venoms/fs/fs_source_policy.zig"),
        .target = target,
        .optimize = optimize,
    });
    const acheron_fs_router_mod = b.createModule(.{
        .root_source_file = b.path("src/acheron/router.zig"),
        .target = target,
        .optimize = optimize,
    });
    acheron_fs_router_mod.addImport("spider-protocol", spider_protocol_module);
    acheron_fs_router_mod.addImport("spiderweb_fs_cache", spiderweb_fs_cache_mod);
    acheron_fs_router_mod.addImport("spiderweb_fs_source_policy", spiderweb_fs_source_policy_mod);
    const spiderweb_mount_provider_mod = b.createModule(.{
        .root_source_file = b.path("src/acheron/mount_provider.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mount_provider_mod.addImport("acheron_fs_router", acheron_fs_router_mod);
    const spiderweb_fs_fuse_adapter_mod = b.createModule(.{
        .root_source_file = b.path("src/venoms/fs/fs_fuse_adapter.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_fs_fuse_adapter_mod.addIncludePath(b.path("src/c"));
    spiderweb_fs_fuse_adapter_mod.addImport("acheron_fs_router", acheron_fs_router_mod);
    spiderweb_fs_fuse_adapter_mod.addImport("spiderweb_mount_provider", spiderweb_mount_provider_mod);
    const fuse_compat_stub_mod = b.createModule(.{
        .root_source_file = b.path("src/c/fuse_compat_stub.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuse_compat_lib = b.addLibrary(.{
        .name = "spiderweb-fuse-compat",
        .root_module = fuse_compat_stub_mod,
        .linkage = .static,
    });
    fuse_compat_lib.addIncludePath(b.path("src/c"));
    fuse_compat_lib.addCSourceFile(.{ .file = b.path("src/c/fuse_compat.c") });
    fuse_compat_lib.linkLibC();

    // Embeddable distributed filesystem module
    const spiderweb_fs_mod = b.addModule("spiderweb_fs", .{
        .root_source_file = b.path("src/venoms/fs/fs_lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_fs_mod.addIncludePath(b.path("src/c"));
    spiderweb_fs_mod.addImport("spider-protocol", spider_protocol_module);
    spiderweb_fs_mod.addImport("spiderweb_node", spiderweb_node_module);
    spiderweb_fs_mod.addImport("spiderweb_fs", spiderweb_fs_protocol_module);
    spiderweb_fs_mod.addImport("spiderweb_fs_cache", spiderweb_fs_cache_mod);
    spiderweb_fs_mod.addImport("acheron_fs_router", acheron_fs_router_mod);
    spiderweb_fs_mod.addImport("spiderweb_fs_fuse_adapter", spiderweb_fs_fuse_adapter_mod);

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
    embed_multi_service_mod.addImport("spider-protocol", spider_protocol_module);
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
    embed_multi_service_example.linkLibrary(fuse_compat_lib);
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

    // Spiderweb workspace host executable
    const spiderweb_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addIncludePath(b.path("src/c"));
    spiderweb_mod.addImport("spider-protocol", spider_protocol_module);
    spiderweb_mod.addImport("spiderweb_node", spiderweb_node_module);
    spiderweb_mod.addImport("spiderweb_fs", spiderweb_fs_protocol_module);
    spiderweb_mod.addImport("spiderweb_fs_cache", spiderweb_fs_cache_mod);
    spiderweb_mod.addImport("spiderweb_fs_source_policy", spiderweb_fs_source_policy_mod);
    spiderweb_mod.addImport("ziggy-memory-store", ziggy_memory_store_module);
    spiderweb_mod.addImport("ziggy-tool-runtime", ziggy_tool_runtime_module);
    spiderweb_mod.addImport("ziggy-runtime-hooks", ziggy_runtime_hooks_module);
    spiderweb_mod.addImport("ziggy-run-orchestrator", ziggy_run_orchestrator_module);

    // Add agent_config module for flat config loading
    const agent_config_mod = b.createModule(.{
        .root_source_file = b.path("src/agents/agent_config.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addImport("agent_config", agent_config_mod);

    const spiderweb = b.addExecutable(.{
        .name = "spiderweb",
        .root_module = spiderweb_mod,
    });
    spiderweb.linkLibrary(fuse_compat_lib);
    applySqliteLibraryPath(spiderweb, sqlite_lib_dir);
    spiderweb.linkLibC();
    spiderweb.linkSystemLibrary("sqlite3");

    b.installArtifact(spiderweb);
    const spiderweb_build_step = b.step("spiderweb", "Build spiderweb server executable");
    spiderweb_build_step.dependOn(&spiderweb.step);
    // Distributed filesystem node executable
    const fs_node_mod = b.createModule(.{
        .root_source_file = b.path("src/venoms/fs/shared/fs_node_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fs_node_mod.addImport("spider-protocol", spider_protocol_module);
    fs_node_mod.addImport("spiderweb_node", spiderweb_node_module);
    const spiderweb_fs_node = b.addExecutable(.{
        .name = "spiderweb-fs-node",
        .root_module = fs_node_mod,
    });
    spiderweb_fs_node.linkLibC();
    b.installArtifact(spiderweb_fs_node);

    // Distributed filesystem mount/router executable
    const fs_mount_mod = b.createModule(.{
        .root_source_file = b.path("src/acheron/mount_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    fs_mount_mod.addIncludePath(b.path("src/c"));
    fs_mount_mod.addImport("spider-protocol", spider_protocol_module);
    fs_mount_mod.addImport("acheron_fs_router", acheron_fs_router_mod);
    fs_mount_mod.addImport("spiderweb_fs_fuse_adapter", spiderweb_fs_fuse_adapter_mod);
    fs_mount_mod.addImport("spiderweb_mount_provider", spiderweb_mount_provider_mod);
    const spiderweb_fs_mount = b.addExecutable(.{
        .name = "spiderweb-fs-mount",
        .root_module = fs_mount_mod,
    });
    spiderweb_fs_mount.linkLibrary(fuse_compat_lib);
    spiderweb_fs_mount.linkLibC();
    b.installArtifact(spiderweb_fs_mount);
    const fs_mount_step = b.step("fs-mount", "Build standalone spiderweb-fs-mount client");
    fs_mount_step.dependOn(&spiderweb_fs_mount.step);

    // Config CLI executable
    const config_mod = b.createModule(.{
        .root_source_file = b.path("src/config_cli.zig"),
        .target = target,
        .optimize = optimize,
    });

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
    const control_build_step = b.step("spiderweb-control", "Build spiderweb-control executable");
    control_build_step.dependOn(&control_cli.step);

    // Run command
    const run_cmd = b.addRunArtifact(spiderweb);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run spiderweb workspace host");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");

    const spiderweb_tests = b.addTest(.{
        .root_module = spiderweb_mod,
    });
    spiderweb_tests.linkLibrary(fuse_compat_lib);
    applySqliteLibraryPath(spiderweb_tests, sqlite_lib_dir);
    spiderweb_tests.linkLibC();
    spiderweb_tests.linkSystemLibrary("sqlite3");
    const run_spiderweb_tests = b.addRunArtifact(spiderweb_tests);
    test_step.dependOn(&run_spiderweb_tests.step);

    const config_tests = b.addTest(.{
        .root_module = config_mod,
    });
    config_tests.linkLibC();
    const run_config_tests = b.addRunArtifact(config_tests);
    test_step.dependOn(&run_config_tests.step);

    const control_tests = b.addTest(.{
        .root_module = control_mod,
    });
    control_tests.linkLibC();
    const run_control_tests = b.addRunArtifact(control_tests);
    test_step.dependOn(&run_control_tests.step);

    const client_tests = b.addTest(.{
        .root_module = acheron_fs_client_mod,
    });
    const run_client_tests = b.addRunArtifact(client_tests);
    test_step.dependOn(&run_client_tests.step);

    const router_tests = b.addTest(.{
        .root_module = acheron_fs_router_mod,
    });
    const run_router_tests = b.addRunArtifact(router_tests);
    test_step.dependOn(&run_router_tests.step);

    const fs_cache_tests = b.addTest(.{
        .root_module = spiderweb_fs_cache_mod,
    });
    const run_fs_cache_tests = b.addRunArtifact(fs_cache_tests);
    test_step.dependOn(&run_fs_cache_tests.step);

    const fs_source_policy_tests = b.addTest(.{
        .root_module = spiderweb_fs_source_policy_mod,
    });
    const run_fs_source_policy_tests = b.addRunArtifact(fs_source_policy_tests);
    test_step.dependOn(&run_fs_source_policy_tests.step);

    const fs_fuse_adapter_tests = b.addTest(.{
        .root_module = spiderweb_fs_fuse_adapter_mod,
    });
    fs_fuse_adapter_tests.linkLibrary(fuse_compat_lib);
    fs_fuse_adapter_tests.linkLibC();
    const run_fs_fuse_adapter_tests = b.addRunArtifact(fs_fuse_adapter_tests);
    test_step.dependOn(&run_fs_fuse_adapter_tests.step);

    const websocket_transport_tests = b.addTest(.{
        .root_module = websocket_transport_mod,
    });
    const run_websocket_transport_tests = b.addRunArtifact(websocket_transport_tests);
    test_step.dependOn(&run_websocket_transport_tests.step);

    const fs_mount_tests = b.addTest(.{
        .root_module = fs_mount_mod,
    });
    fs_mount_tests.linkLibrary(fuse_compat_lib);
    fs_mount_tests.linkLibC();
    const run_fs_mount_tests = b.addRunArtifact(fs_mount_tests);
    test_step.dependOn(&run_fs_mount_tests.step);
    const fs_mount_test_step = b.step("test-fs-mount", "Run spiderweb-fs-mount client tests");
    fs_mount_test_step.dependOn(&run_fs_mount_tests.step);
}

fn applySqliteLibraryPath(compile: *std.Build.Step.Compile, sqlite_lib_dir: ?[]const u8) void {
    if (sqlite_lib_dir) |dir| {
        compile.addLibraryPath(.{ .cwd_relative = dir });
    }
}
