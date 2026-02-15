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

    // Spiderweb executable
    const spiderweb_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_mod.addImport("ziggy-piai", ziggy_piai_module);

    const spiderweb = b.addExecutable(.{
        .name = "spiderweb",
        .root_module = spiderweb_mod,
    });
    spiderweb.linkLibC();

    b.installArtifact(spiderweb);

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

    const spiderweb_tests = b.addTest(.{
        .root_module = test_mod,
    });
    spiderweb_tests.linkLibC();

    const run_tests = b.addRunArtifact(spiderweb_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}