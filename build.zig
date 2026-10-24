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

    const version = comptime parseVersion(build_zon);

    const core_options = b.addOptions();
    core_options.addOption([]const u8, "version", version);
    core_options.addOption(bool, "pthread_threads", false);
    const core_options_mod = core_options.createModule();

    const ffi_options = b.addOptions();
    ffi_options.addOption([]const u8, "version", version);
    ffi_options.addOption(bool, "pthread_threads", true);
    const ffi_options_mod = ffi_options.createModule();

    const core_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    core_mod.addImport("build_options", core_options_mod);

    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });
    ffi_mod.addImport("build_options", ffi_options_mod);

    const static_lib = b.addLibrary(.{
        .linkage = .static,
        .name = "vrouter",
        .root_module = ffi_mod,
    });
    b.installArtifact(static_lib);
    static_lib.installHeader(b.path("include/vrouter.h"), "vrouter.h");

    const shared_lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "vrouter",
        .root_module = ffi_mod,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
    });
    shared_lib.linker_allow_shlib_undefined = true;
    b.installArtifact(shared_lib);

    if (is_linux and !is_android) {
        const exe_mod = b.createModule(.{
            .root_source_file = b.path("exec/vrouter/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vrouter", .module = core_mod },
            },
        });

        const exe = b.addExecutable(.{
            .name = "vrouter",
            .root_module = exe_mod,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (@hasField(std.Build, "args")) {
            if (b.args) |args| run_cmd.addArgs(args);
        } else {
            run_cmd.addPassthruArgs();
        }

        const run_step = b.step("run", "Run vRouter");
        run_step.dependOn(&run_cmd.step);

        const daemon_mod = b.createModule(.{
            .root_source_file = b.path("exec/vrouterd/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vrouter", .module = core_mod },
            },
        });

        const daemon = b.addExecutable(.{
            .name = "vrouterd",
            .root_module = daemon_mod,
        });
        b.installArtifact(daemon);
    }

    const test_mod = b.createModule(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("build_options", core_options_mod);

    const test_filter = b.option([]const u8, "test-filter", "Only run tests containing this substring");
    const test_filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
        .filters = test_filters,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const ffi_smoke_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ffi_smoke_mod.addCSourceFile(.{
        .file = b.path("test/ffi_smoke.c"),
        .flags = &.{"-std=c11"},
    });
    ffi_smoke_mod.addIncludePath(b.path("include"));
    ffi_smoke_mod.linkLibrary(shared_lib);

    const ffi_smoke = b.addExecutable(.{
        .name = "ffi-smoke",
        .root_module = ffi_smoke_mod,
    });
    const run_ffi_smoke = b.addRunArtifact(ffi_smoke);
    test_step.dependOn(&run_ffi_smoke.step);
}
