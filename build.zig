const std = @import("std");

const build_zon = @embedFile("build.zig.zon");

fn parseVersion(comptime zon: []const u8) []const u8 {
    const marker = ".version = \"";
    const start = (std.mem.indexOf(u8, zon, marker) orelse
        @compileError("build.zig.zon is missing .version")) + marker.len;
    const end = std.mem.indexOfScalarPos(u8, zon, start, '"') orelse
        @compileError("build.zig.zon version string is unterminated");
    return zon[start..end];
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const target_os = target.result.os.tag;
    const target_abi = target.result.abi;
    const is_linux = target_os == .linux;
    const is_android = is_linux and
        (target_abi == .android or target_abi == .androideabi);

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", comptime parseVersion(build_zon));
    const build_options_mod = build_options.createModule();

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("build_options", build_options_mod);

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vnat",
        .root_module = lib_mod,
    });
    b.installArtifact(static_lib);

    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "vnat",
        .root_module = lib_mod,
        .version = .{ .major = 0, .minor = 0, .patch = 1 },
    });
    b.installArtifact(shared_lib);

    if (is_linux and !is_android) {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path("exec/vnat/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vnat", .module = lib_mod },
            },
        });

        const exe = b.addExecutable(.{
            .name = "vnat",
            .root_module = exe_mod,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);

        const run_step = b.step("run", "Run vnat");
        run_step.dependOn(&run_cmd.step);

        const daemon_mod = b.createModule(.{
            .root_source_file = b.path("exec/vnatd/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vnat", .module = lib_mod },
            },
        });

        const daemon = b.addExecutable(.{
            .name = "vnatd",
            .root_module = daemon_mod,
        });
        b.installArtifact(daemon);
    }

    const test_mod = b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("build_options", build_options_mod);

    const test_filter = b.option([]const u8, "test-filter", "Only run tests containing this substring");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
        .filters = test_filters,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
