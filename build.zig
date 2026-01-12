const std = @import("std");

// ==============================================================================
// C 编译标志
// ==============================================================================
const c_flags = [_][]const u8{
    "-std=c11",
    "-fPIC",
    "-D_GNU_SOURCE",
    "-D_DEFAULT_SOURCE",
    "-DPTLS_WITHOUT_FUSION",
    "-DPICOQUIC_LIBRARY",
    "-DPICOTLS_USE_OPENSSL",
    "-ffunction-sections",
    "-fdata-sections",
    "-fvisibility=hidden",
    "-Wno-error",
    "-fno-sanitize=undefined",
};

// ==============================================================================
// picoquic 源文件
// ==============================================================================
const picoquic_sources = [_][]const u8{
    "libs/picoquic/picoquic/bbr.c",
    "libs/picoquic/picoquic/bbr1.c",
    "libs/picoquic/picoquic/bytestream.c",
    "libs/picoquic/picoquic/c4.c",
    "libs/picoquic/picoquic/cc_common.c",
    "libs/picoquic/picoquic/config.c",
    "libs/picoquic/picoquic/cubic.c",
    "libs/picoquic/picoquic/ech.c",
    "libs/picoquic/picoquic/error_names.c",
    "libs/picoquic/picoquic/fastcc.c",
    "libs/picoquic/picoquic/frames.c",
    "libs/picoquic/picoquic/intformat.c",
    "libs/picoquic/picoquic/logger.c",
    "libs/picoquic/picoquic/logwriter.c",
    "libs/picoquic/picoquic/loss_recovery.c",
    "libs/picoquic/picoquic/newreno.c",
    "libs/picoquic/picoquic/pacing.c",
    "libs/picoquic/picoquic/packet.c",
    "libs/picoquic/picoquic/paths.c",
    "libs/picoquic/picoquic/performance_log.c",
    "libs/picoquic/picoquic/picohash.c",
    "libs/picoquic/picoquic/picoquic_lb.c",
    "libs/picoquic/picoquic/picoquic_ptls_openssl.c",
    "libs/picoquic/picoquic/picoquic_ptls_minicrypto.c",
    "libs/picoquic/picoquic/picosocks.c",
    "libs/picoquic/picoquic/picosplay.c",
    "libs/picoquic/picoquic/port_blocking.c",
    "libs/picoquic/picoquic/prague.c",
    "libs/picoquic/picoquic/quicctx.c",
    "libs/picoquic/picoquic/register_all_cc_algorithms.c",
    "libs/picoquic/picoquic/sacks.c",
    "libs/picoquic/picoquic/sender.c",
    "libs/picoquic/picoquic/sim_link.c",
    "libs/picoquic/picoquic/siphash.c",
    "libs/picoquic/picoquic/sockloop.c",
    "libs/picoquic/picoquic/spinbit.c",
    "libs/picoquic/picoquic/ticket_store.c",
    "libs/picoquic/picoquic/timing.c",
    "libs/picoquic/picoquic/token_store.c",
    "libs/picoquic/picoquic/tls_api.c",
    "libs/picoquic/picoquic/transport.c",
    "libs/picoquic/picoquic/unified_log.c",
    "libs/picoquic/picoquic/util.c",
};

// ==============================================================================
// picoquic loglib 源文件
// ==============================================================================
const loglib_sources = [_][]const u8{
    "libs/picoquic/loglib/autoqlog.c",
    "libs/picoquic/loglib/cidset.c",
    "libs/picoquic/loglib/csv.c",
    "libs/picoquic/loglib/logconvert.c",
    "libs/picoquic/loglib/logreader.c",
    "libs/picoquic/loglib/qlog.c",
    "libs/picoquic/loglib/svg.c",
};

// ==============================================================================
// picotls 核心源文件
// ==============================================================================
const picotls_sources = [_][]const u8{
    "libs/picotls/lib/asn1.c",
    "libs/picotls/lib/hpke.c",
    "libs/picotls/lib/pembase64.c",
    "libs/picotls/lib/picotls.c",
    "libs/picotls/lib/openssl.c",
    "libs/picotls/lib/ffx.c",
    "libs/picotls/lib/uecc.c",
    "libs/picotls/lib/cifra.c",
    "libs/picotls/lib/minicrypto-pem.c",
};

// ==============================================================================
// picotls cifra 包装源文件
// ==============================================================================
const picotls_cifra_sources = [_][]const u8{
    "libs/picotls/lib/cifra/aes128.c",
    "libs/picotls/lib/cifra/aes256.c",
    "libs/picotls/lib/cifra/chacha20.c",
    "libs/picotls/lib/cifra/random.c",
    "libs/picotls/lib/cifra/x25519.c",
};

// ==============================================================================
// cifra 加密库源文件
// ==============================================================================
const cifra_sources = [_][]const u8{
    "libs/picotls/deps/cifra/src/aes.c",
    "libs/picotls/deps/cifra/src/blockwise.c",
    "libs/picotls/deps/cifra/src/chacha20.c",
    "libs/picotls/deps/cifra/src/chash.c",
    "libs/picotls/deps/cifra/src/curve25519.c",
    "libs/picotls/deps/cifra/src/drbg.c",
    "libs/picotls/deps/cifra/src/gcm.c",
    "libs/picotls/deps/cifra/src/gf128.c",
    "libs/picotls/deps/cifra/src/hmac.c",
    "libs/picotls/deps/cifra/src/modes.c",
    "libs/picotls/deps/cifra/src/poly1305.c",
    "libs/picotls/deps/cifra/src/sha256.c",
    "libs/picotls/deps/cifra/src/sha512.c",
};

// ==============================================================================
// micro-ecc 源文件
// ==============================================================================
const micro_ecc_sources = [_][]const u8{
    "libs/picotls/deps/micro-ecc/uECC.c",
};

// ==============================================================================
// 头文件路径
// ==============================================================================
const include_dirs = [_][]const u8{
    "libs/picoquic",
    "libs/picoquic/picoquic",
    "libs/picoquic/loglib",
    "libs/picotls/include",
    "libs/picotls/deps/cifra/src",
    "libs/picotls/deps/cifra/src/ext",
    "libs/picotls/deps/micro-ecc",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ==========================================================================
    // libxev 依赖
    // ==========================================================================
    const dep_xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    // ==========================================================================
    // picoquic 静态库
    // ==========================================================================
    const picoquic_lib = b.addLibrary(.{
        .name = "picoquic",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    // 添加所有 C 源文件
    picoquic_lib.addCSourceFiles(.{ .files = &picoquic_sources, .flags = &c_flags });
    picoquic_lib.addCSourceFiles(.{ .files = &loglib_sources, .flags = &c_flags });
    picoquic_lib.addCSourceFiles(.{ .files = &picotls_sources, .flags = &c_flags });
    picoquic_lib.addCSourceFiles(.{ .files = &picotls_cifra_sources, .flags = &c_flags });
    picoquic_lib.addCSourceFiles(.{ .files = &cifra_sources, .flags = &c_flags });
    picoquic_lib.addCSourceFiles(.{ .files = &micro_ecc_sources, .flags = &c_flags });

    // 添加头文件路径
    for (include_dirs) |inc| {
        picoquic_lib.addIncludePath(b.path(inc));
    }

    // 链接 C 标准库
    picoquic_lib.linkLibC();

    // 链接 OpenSSL
    picoquic_lib.linkSystemLibrary("crypto");
    picoquic_lib.linkSystemLibrary("ssl");

    // 平台特定链接
    switch (target.result.os.tag) {
        .linux => {
            picoquic_lib.linkSystemLibrary("pthread");
            picoquic_lib.linkSystemLibrary("m");
            picoquic_lib.linkSystemLibrary("dl");
        },
        .windows => {
            picoquic_lib.linkSystemLibrary("ws2_32");
            picoquic_lib.linkSystemLibrary("bcrypt");
        },
        else => {},
    }

    b.installArtifact(picoquic_lib);

    // ==========================================================================
    // 主程序
    // ==========================================================================
    const exe = b.addExecutable(.{
        .name = "lyune_gateway",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // 添加模块
    exe.root_module.addImport("xev", dep_xev.module("xev"));

    // 添加头文件路径（让 Zig 可以 @cImport）
    for (include_dirs) |inc| {
        exe.addIncludePath(b.path(inc));
    }

    // 链接 picoquic 静态库
    exe.linkLibrary(picoquic_lib);

    // 链接系统库
    exe.linkLibC();
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("ssl");

    switch (target.result.os.tag) {
        .linux => {
            exe.linkSystemLibrary("pthread");
            exe.linkSystemLibrary("m");
            exe.linkSystemLibrary("dl");
        },
        .windows => {
            exe.linkSystemLibrary("ws2_32");
            exe.linkSystemLibrary("bcrypt");
        },
        else => {},
    }

    b.installArtifact(exe);

    // ==========================================================================
    // run 命令
    // ==========================================================================
    const run_step = b.step("run", "Run the gateway");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // ==========================================================================
    // test 命令
    // ==========================================================================
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    exe_tests.linkLibrary(picoquic_lib);
    exe_tests.linkLibC();
    exe_tests.linkSystemLibrary("crypto");
    exe_tests.linkSystemLibrary("ssl");

    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
