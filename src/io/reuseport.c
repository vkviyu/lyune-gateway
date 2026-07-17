/*
 * reuseport 分类器（Linux classic BPF / cBPF）
 *
 * 目标：让内核在 SO_REUSEPORT socket 组内，按 QUIC 数据包里的服务端 CID 选择目标
 * socket，从而把同一条连接的包稳定投递给固定的 Worker，实现零锁连接亲和。
 *
 * 本文件提供两个入口：
 *   - lyune_classify_quic_packet：纯 C 实现的分流逻辑，供 Zig 侧单元测试比对（见
 *     reuseport.zig），保证下面手写的 BPF 字节码逻辑正确；
 *   - lyune_attach_reuseport_classifier：把等价逻辑的 cBPF 程序 attach 到 socket。
 *
 * CID 布局（与 cid.zig 保持一致）：['L','Y', version, worker_id, entropy(4)]，共 8 字节。
 * 不匹配（握手期 Initial、外部 CID、越界 worker_id）时返回 UINT32_MAX，内核回退默认哈希。
 */

#include <stddef.h>
#include <stdint.h>

#define LYUNE_CID_LENGTH 8u
#define LYUNE_CID_MAGIC_0 0x4cu       /* 'L' */
#define LYUNE_CID_MAGIC_1 0x59u       /* 'Y' */
#define LYUNE_CID_VERSION 1u
#define LYUNE_REUSEPORT_FALLBACK UINT32_MAX /* 让内核回退到默认 reuseport 哈希 */

/*
 * 纯 C 参考实现：从一个 QUIC UDP 包里解析 worker_id。
 * 与下面的 BPF 程序逻辑一一对应，仅用于测试验证，不在生产收包路径执行。
 */
uint32_t lyune_classify_quic_packet(const uint8_t *packet, size_t length,
                                    uint32_t socket_count)
{
    size_t cid_offset;

    /* 至少要能容纳短包头下的完整 8 字节 CID（首字节 + CID）。 */
    if (packet == NULL || length < 9 || socket_count == 0) {
        return LYUNE_REUSEPORT_FALLBACK;
    }

    if ((packet[0] & 0x80u) != 0) {
        /* 长包头：byte5 是 DCID 长度，DCID 从 byte6 起；要求长度恰为 8。 */
        if (length < 14 || packet[5] != LYUNE_CID_LENGTH) {
            return LYUNE_REUSEPORT_FALLBACK;
        }
        cid_offset = 6;
    } else {
        /* 短包头：DCID 紧跟首字节，从 byte1 起。 */
        cid_offset = 1;
    }

    /* 校验魔数 + 版本 + worker_id 在合法范围，任一不符都回退。 */
    if (packet[cid_offset] != LYUNE_CID_MAGIC_0 ||
        packet[cid_offset + 1] != LYUNE_CID_MAGIC_1 ||
        packet[cid_offset + 2] != LYUNE_CID_VERSION ||
        packet[cid_offset + 3] >= socket_count) {
        return LYUNE_REUSEPORT_FALLBACK;
    }

    return packet[cid_offset + 3];
}

#if defined(__linux__)

#include <linux/filter.h>
#include <sys/socket.h>

/*
 * 把与上面等价的 cBPF 程序 attach 到 socket 组。
 *
 * 手写 BPF 是"跳转偏移"编程：每条指令的 (jt, jf) 是相对后续指令的条数。任何插入/删除
 * 指令都必须重新核对所有偏移，因此右侧标注了指令序号，且逻辑与 lyune_classify_quic_packet
 * 完全对应，改动时务必同步两边并跑 reuseport.zig 的等价测试。
 *
 * BPF_LEN 读取的是整包长度；BPF_B|BPF_ABS 读取指定偏移的一个字节。
 * 命中时 BPF_RET|BPF_A 返回累加器里的 worker_id；不命中统一跳到末尾返回 FALLBACK。
 */
int lyune_attach_reuseport_classifier(int fd, uint32_t socket_count)
{
    struct sock_filter code[] = {
        /* 包长不足以容纳短包头 CID，直接回退。 */
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),                         /*  0 */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 9, 0, 24),                /*  1 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),                        /*  2 */
        /* 首字节最高位区分长/短包头：置位跳到长包头分支(指令13)。 */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80, 9, 0),             /*  3 */

        /* ===== 短包头分支：CID 从 byte1 起 ===== */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1),                        /*  4 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_MAGIC_0, 0, 20), /* 5 校验 'L' */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),                        /*  6 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_MAGIC_1, 0, 18), /* 7 校验 'Y' */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 3),                        /*  8 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_VERSION, 0, 16), /* 9 校验版本 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 4),                        /* 10 读 worker_id */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, socket_count, 14, 0),     /* 11 越界则回退 */
        BPF_STMT(BPF_RET | BPF_A, 0),                                 /* 12 返回 worker_id */

        /* ===== 长包头分支：byte5=DCID 长度，CID 从 byte6 起 ===== */
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),                        /* 13 */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 14, 0, 11),               /* 14 长度不足则回退 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 5),                        /* 15 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_LENGTH, 0, 9),  /* 16 DCID 长度须为 8 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),                        /* 17 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_MAGIC_0, 0, 7), /* 18 校验 'L' */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 7),                        /* 19 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_MAGIC_1, 0, 5), /* 20 校验 'Y' */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 8),                        /* 21 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, LYUNE_CID_VERSION, 0, 3), /* 22 校验版本 */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),                        /* 23 读 worker_id */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, socket_count, 1, 0),      /* 24 越界则回退 */
        BPF_STMT(BPF_RET | BPF_A, 0),                                 /* 25 返回 worker_id */

        /* 无效索引：让内核使用默认 reuseport 哈希分发。 */
        BPF_STMT(BPF_RET | BPF_K, LYUNE_REUSEPORT_FALLBACK),          /* 26 */
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
        .filter = code,
    };

    /* attach 到组内任一 fd，内核会应用到整个 reuseport 组。 */
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
                      &program, sizeof(program));
}

#else

/* 非 Linux 平台没有 reuseport cBPF：返回成功，由默认哈希分发 + 用户态兜底交接。 */
int lyune_attach_reuseport_classifier(int fd, uint32_t socket_count)
{
    (void)fd;
    (void)socket_count;
    return 0;
}

#endif
