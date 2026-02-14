const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Spiderweb executable
    const spiderweb = b.addExecutable(.{
        .name = "spiderweb",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(spiderweb);

    // Run command
    const run_cmd = b.addRunArtifact(spiderweb);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run spiderweb");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const spiderweb_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_tests = b.addRunArtifact(spiderweb_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}