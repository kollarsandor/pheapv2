const std = @import("std");

const SRC_FILES = [_][]const u8{
    "header.zig", "wal.zig",       "security.zig", "concurrency.zig",
    "gc.zig",     "transaction.zig","recovery.zig", "schema.zig",
    "gpu.zig",    "api.zig",       "benchmark.zig",
};

const C_FILES = [_][]const u8{
    "pheap.zig", "allocator.zig", "pointer.zig", "snapshot.zig",
};

fn registerModules(b: *std.Build, root_module: anytype) void {
    var src_mods: [SRC_FILES.len]*std.Build.Module = undefined;
    var c_mods: [C_FILES.len]*std.Build.Module = undefined;

    for (SRC_FILES, 0..) |f, i| {
        src_mods[i] = b.createModule(.{ .root_source_file = b.path(b.fmt("src/{s}", .{f})) });
    }
    for (C_FILES, 0..) |f, i| {
        c_mods[i] = b.createModule(.{ .root_source_file = b.path(b.fmt("c/{s}", .{f})) });
    }

    // Cross-link every module against every other module so any @import("X.zig") works.
    const all_mods_len = SRC_FILES.len + C_FILES.len;
    var all_mods: [all_mods_len]*std.Build.Module = undefined;
    var all_names: [all_mods_len][]const u8 = undefined;
    inline for (SRC_FILES, 0..) |f, i| { all_mods[i] = src_mods[i]; all_names[i] = f; }
    inline for (C_FILES, 0..) |f, i| { all_mods[SRC_FILES.len + i] = c_mods[i]; all_names[SRC_FILES.len + i] = f; }

    var i: usize = 0;
    while (i < all_mods.len) : (i += 1) {
        var j: usize = 0;
        while (j < all_mods.len) : (j += 1) {
            if (i == j) continue;
            @constCast(all_mods[i]).addImport(all_names[j], @constCast(all_mods[j]));
        }
    }
    i = 0;
    while (i < all_mods.len) : (i += 1) {
        root_module.addImport(all_names[i], @constCast(all_mods[i]));
    }
}

fn linkOpenssl(b: *std.Build, comp: *std.Build.Step.Compile) void {
    _ = b;
    const openssl_lib = "/nix/store/5xmcl9wr18g6ym3dh3363hv8hp6jyxqd-openssl-3.4.1/lib";
    const openssl_inc = "/nix/store/0225zs9jl9s2y3ai1arbg0h9z7z4bmfi-openssl-3.4.1-dev/include";
    comp.linkLibC();
    comp.addIncludePath(.{ .cwd_relative = openssl_inc });
    comp.addLibraryPath(.{ .cwd_relative = openssl_lib });
    comp.linkSystemLibrary("crypto");
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "pheap-runtime",
        .root_source_file = b.path("c/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkOpenssl(b, exe);
    exe.addIncludePath(b.path("c"));
    exe.addIncludePath(b.path("src"));
    if (target.result.os.tag == .linux) {
        exe.linkSystemLibrary("pthread");
        exe.linkSystemLibrary("dl");
    }
    registerModules(b, &exe.root_module);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);

    const lib_tests = b.addTest(.{
        .root_source_file = b.path("c/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkOpenssl(b, lib_tests);
    lib_tests.addIncludePath(b.path("c"));
    lib_tests.addIncludePath(b.path("src"));
    registerModules(b, &lib_tests.root_module);
    const run_lib_unit_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const cli_tool = b.addExecutable(.{
        .name = "pheap-tool",
        .root_source_file = b.path("c/inspect.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkOpenssl(b, cli_tool);
    cli_tool.addIncludePath(b.path("c"));
    cli_tool.addIncludePath(b.path("src"));
    registerModules(b, &cli_tool.root_module);
    b.installArtifact(cli_tool);

    const repair_tool = b.addExecutable(.{
        .name = "pheap-repair",
        .root_source_file = b.path("c/repair.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkOpenssl(b, repair_tool);
    repair_tool.addIncludePath(b.path("c"));
    repair_tool.addIncludePath(b.path("src"));
    registerModules(b, &repair_tool.root_module);
    b.installArtifact(repair_tool);

    const benchmark_tool = b.addExecutable(.{
        .name = "pheap-bench",
        .root_source_file = b.path("src/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    linkOpenssl(b, benchmark_tool);
    benchmark_tool.addIncludePath(b.path("c"));
    benchmark_tool.addIncludePath(b.path("src"));
    registerModules(b, &benchmark_tool.root_module);
    b.installArtifact(benchmark_tool);
}
