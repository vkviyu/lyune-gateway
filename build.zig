const std = @import("std");

const c_ares_flags = [_][]const u8{
    "-std=c11",
    "-fPIC",
    "-D_GNU_SOURCE",
    "-D_DEFAULT_SOURCE",
    "-DCARES_STATICLIB",
    "-DHAVE_SYS_TYPES_H=1",
    "-DHAVE_SYS_TIME_H=1",
    "-DHAVE_SYS_SOCKET_H=1",
    "-DHAVE_SYS_SELECT_H=1",
    "-DHAVE_SYS_UIO_H=1",
    "-DHAVE_SYS_IOCTL_H=1",
    "-DHAVE_TIME_H=1",
    "-DHAVE_UNISTD_H=1",
    "-DHAVE_ARPA_INET_H=1",
    "-DHAVE_NETINET_IN_H=1",
    "-DHAVE_NETDB_H=1",
    "-DHAVE_POLL_H=1",
    "-DHAVE_FCNTL_H=1",
    "-DHAVE_ERRNO_H=1",
    "-DHAVE_LIMITS_H=1",
    "-DHAVE_STDINT_H=1",
    "-DHAVE_STDLIB_H=1",
    "-DHAVE_STRING_H=1",
    "-DHAVE_STRINGS_H=1",
    "-DHAVE_STRUCT_TIMEVAL=1",
    "-DHAVE_AF_INET6=1",
    "-DHAVE_PF_INET6=1",
    "-DHAVE_STRUCT_ADDRINFO=1",
    "-DHAVE_STRUCT_IN6_ADDR=1",
    "-DHAVE_STRUCT_SOCKADDR_IN6=1",
    "-DHAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID=1",
    "-DHAVE_SOCKLEN_T=1",
    "-DHAVE_RECV=1",
    "-DHAVE_SEND=1",
    "-DHAVE_RECVFROM=1",
    "-DHAVE_SENDTO=1",
    "-DHAVE_SOCKET=1",
    "-DHAVE_CONNECT=1",
    "-DHAVE_CLOSE=1",
    "-DHAVE_FCNTL=1",
    "-DHAVE_FCNTL_O_NONBLOCK=1",
    "-DHAVE_IOCTL=1",
    "-DHAVE_WRITEV=1",
    "-DHAVE_GETENV=1",
    "-DHAVE_GETTIMEOFDAY=1",
    "-DHAVE_CLOCK_GETTIME_MONOTONIC=1",
    "-DRECVFROM_TYPE_ARG3=size_t",
    "-DSEND_TYPE_ARG1=int",
    "-DSEND_TYPE_ARG2=const void *",
    "-DSEND_TYPE_ARG3=size_t",
    "-DSEND_TYPE_ARG4=int",
    "-DSEND_TYPE_RETV=ssize_t",
    "-DSEND_QUAL_ARG2=const",
    "-ffunction-sections",
    "-fdata-sections",
    "-Wno-error",
};

const c_ares_sources = [_][]const u8{
    "ares_addrinfo2hostent.c",
    "ares_addrinfo_localhost.c",
    "ares_android.c",
    "ares_cancel.c",
    "ares_close_sockets.c",
    "ares_conn.c",
    "ares_cookie.c",
    "ares_data.c",
    "ares_destroy.c",
    "ares_free_hostent.c",
    "ares_free_string.c",
    "ares_freeaddrinfo.c",
    "ares_getaddrinfo.c",
    "ares_getenv.c",
    "ares_gethostbyaddr.c",
    "ares_gethostbyname.c",
    "ares_getnameinfo.c",
    "ares_hosts_file.c",
    "ares_init.c",
    "ares_library_init.c",
    "ares_metrics.c",
    "ares_options.c",
    "ares_parse_into_addrinfo.c",
    "ares_process.c",
    "ares_qcache.c",
    "ares_query.c",
    "ares_search.c",
    "ares_send.c",
    "ares_set_socket_functions.c",
    "ares_socket.c",
    "ares_sortaddrinfo.c",
    "ares_strerror.c",
    "ares_sysconfig.c",
    "ares_sysconfig_files.c",
    "ares_sysconfig_mac.c",
    "ares_sysconfig_win.c",
    "ares_timeout.c",
    "ares_update_servers.c",
    "ares_version.c",
    "dsa/ares_array.c",
    "dsa/ares_htable.c",
    "dsa/ares_htable_asvp.c",
    "dsa/ares_htable_dict.c",
    "dsa/ares_htable_strvp.c",
    "dsa/ares_htable_szvp.c",
    "dsa/ares_htable_vpstr.c",
    "dsa/ares_htable_vpvp.c",
    "dsa/ares_llist.c",
    "dsa/ares_slist.c",
    "event/ares_event_configchg.c",
    "event/ares_event_epoll.c",
    "event/ares_event_kqueue.c",
    "event/ares_event_poll.c",
    "event/ares_event_select.c",
    "event/ares_event_thread.c",
    "inet_net_pton.c",
    "inet_ntop.c",
    "legacy/ares_create_query.c",
    "legacy/ares_expand_name.c",
    "legacy/ares_expand_string.c",
    "legacy/ares_fds.c",
    "legacy/ares_getsock.c",
    "legacy/ares_parse_a_reply.c",
    "legacy/ares_parse_aaaa_reply.c",
    "legacy/ares_parse_caa_reply.c",
    "legacy/ares_parse_mx_reply.c",
    "legacy/ares_parse_naptr_reply.c",
    "legacy/ares_parse_ns_reply.c",
    "legacy/ares_parse_ptr_reply.c",
    "legacy/ares_parse_soa_reply.c",
    "legacy/ares_parse_srv_reply.c",
    "legacy/ares_parse_txt_reply.c",
    "legacy/ares_parse_uri_reply.c",
    "record/ares_dns_mapping.c",
    "record/ares_dns_multistring.c",
    "record/ares_dns_name.c",
    "record/ares_dns_parse.c",
    "record/ares_dns_record.c",
    "record/ares_dns_write.c",
    "str/ares_buf.c",
    "str/ares_str.c",
    "str/ares_strsplit.c",
    "util/ares_iface_ips.c",
    "util/ares_threads.c",
    "util/ares_timeval.c",
    "util/ares_math.c",
    "util/ares_rand.c",
    "util/ares_uri.c",
};

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
    "libs/picotls/include",
    "libs/picotls/deps/cifra/src",
    "libs/picotls/deps/cifra/src/ext",
    "libs/picotls/deps/micro-ecc",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_integration_tests = b.option(bool, "enable-integration-tests", "Run tests that require external services") orelse false;
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_integration_tests", enable_integration_tests);

    // ==========================================================================
    // libxev 依赖
    // ==========================================================================
    const dep_xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const c_ares_dep = b.dependency("c_ares", .{});
    const boringssl_dep = b.dependency("boringssl", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl = boringssl_dep.artifact("boringssl");

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
    picoquic_lib.root_module.addCSourceFiles(.{ .files = &picoquic_sources, .flags = &c_flags });
    picoquic_lib.root_module.addCSourceFiles(.{ .files = &picotls_sources, .flags = &c_flags });
    picoquic_lib.root_module.addCSourceFiles(.{ .files = &picotls_cifra_sources, .flags = &c_flags });
    picoquic_lib.root_module.addCSourceFiles(.{ .files = &cifra_sources, .flags = &c_flags });
    picoquic_lib.root_module.addCSourceFiles(.{ .files = &micro_ecc_sources, .flags = &c_flags });

    // 添加头文件路径
    for (include_dirs) |inc| {
        picoquic_lib.root_module.addIncludePath(b.path(inc));
    }
    picoquic_lib.root_module.linkLibrary(boringssl);

    // 链接 C 标准库
    picoquic_lib.root_module.link_libc = true;

    // TLS symbols are provided by the vendored BoringSSL artifacts on the final target.

    // 平台特定链接
    switch (target.result.os.tag) {
        .linux => {
            picoquic_lib.root_module.linkSystemLibrary("pthread", .{});
            picoquic_lib.root_module.linkSystemLibrary("m", .{});
            picoquic_lib.root_module.linkSystemLibrary("dl", .{});
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
    exe.root_module.addImport("build_options", build_options.createModule());

    // 添加头文件路径（让 Zig 可以 @cImport）
    for (include_dirs) |inc| {
        exe.root_module.addIncludePath(b.path(inc));
    }
    exe.root_module.addIncludePath(c_ares_dep.path("include"));
    exe.root_module.addIncludePath(c_ares_dep.path("src/lib"));
    exe.root_module.addIncludePath(c_ares_dep.path("src/lib/include"));
    exe.root_module.addCSourceFiles(.{
        .root = c_ares_dep.path("src/lib"),
        .files = &c_ares_sources,
        .flags = &c_ares_flags,
    });
    exe.root_module.addCSourceFile(.{
        .file = b.path("src/io/reuseport.c"),
        .flags = &.{"-std=c11"},
    });
    exe.root_module.linkLibrary(picoquic_lib);
    exe.root_module.linkLibrary(boringssl);

    switch (target.result.os.tag) {
        .linux => {
            exe.root_module.linkSystemLibrary("pthread", .{});
            exe.root_module.linkSystemLibrary("m", .{});
            exe.root_module.linkSystemLibrary("dl", .{});
        },
        else => {},
    }

    b.installArtifact(exe);

    const release_step = b.step("release", "Build a self-contained release bundle");
    const install_release_exe = b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .{ .custom = "release/bin" } },
    });
    const install_release_config = b.addInstallFileWithDir(
        b.path("config/gateway.json"),
        .{ .custom = "release/config" },
        "gateway.json",
    );
    release_step.dependOn(&install_release_exe.step);
    release_step.dependOn(&install_release_config.step);

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
    exe_tests.root_module.addIncludePath(c_ares_dep.path("include"));

    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
