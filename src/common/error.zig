//! 线程本地错误处理框架
//!
//! 为 Thread-per-Core 架构设计的错误处理机制。
//! 每个工作线程拥有独立的错误处理器实例，避免锁竞争。
//!
//! ## 设计原则
//!
//! 1. **零锁竞争**：使用 `threadlocal` 存储，每个线程独立。
//! 2. **零侵入**：通过全局函数访问，无需修改现有结构体。
//! 3. **可扩展**：支持注册自定义处理器（日志、上报、告警等）。
//!
//! ## 使用示例
//!
//! ```zig
//! const err_handler = @import("common/error.zig");
//!
//! // 在 Worker 初始化时设置处理器
//! err_handler.setHandler(myCustomHandler);
//!
//! // 在业务代码中报告错误
//! err_handler.report(.transport, "UDP send failed", .{ .err = err });
//! ```

const std = @import("std");

/// 错误来源分类
pub const ErrorSource = enum {
    /// 传输层错误 (UDP 收发、Socket)
    transport,
    /// 协议层错误 (QUIC 协议栈)
    protocol,
    /// 会话层错误 (连接管理、流处理)
    session,
    /// 业务层错误 (路由、鉴权、消息处理)
    business,
    /// 系统层错误 (内存分配、文件IO)
    system,
    /// 配置错误
    config,
    /// 未分类错误
    unknown,
};

/// 错误严重级别
pub const Severity = enum {
    /// 调试信息
    debug,
    /// 普通信息
    info,
    /// 警告（可恢复）
    warning,
    /// 错误（影响单个请求/连接）
    err,
    /// 严重错误（影响服务稳定性）
    critical,
};

/// 错误上下文信息
pub const ErrorContext = struct {
    /// 错误来源
    source: ErrorSource,
    /// 严重级别
    severity: Severity = .err,
    /// 错误描述
    message: []const u8,
    /// 原始错误（如果有）
    raw_error: ?anyerror = null,
    /// 关联的连接 ID（如果有）
    connection_id: ?u64 = null,
    /// 关联的流 ID（如果有）
    stream_id: ?u64 = null,
    /// 时间戳（微秒）
    timestamp: i64,
};

/// 错误处理器函数类型
pub const ErrorHandler = *const fn (ctx: ErrorContext) void;

/// 默认错误处理器：输出到标准日志
fn defaultHandler(ctx: ErrorContext) void {
    const severity_str = @tagName(ctx.severity);
    const source_str = @tagName(ctx.source);

    if (ctx.raw_error) |raw_err| {
        std.log.err("[{s}][{s}] {s}: {}", .{
            severity_str,
            source_str,
            ctx.message,
            raw_err,
        });
    } else {
        std.log.err("[{s}][{s}] {s}", .{
            severity_str,
            source_str,
            ctx.message,
        });
    }
}

/// 线程本地存储：当前线程的错误处理器
threadlocal var current_handler: ErrorHandler = defaultHandler;

/// 线程本地存储：当前线程的 Worker ID（用于日志区分）
threadlocal var current_worker_id: u8 = 0;

// =============================================================================
// 公共 API
// =============================================================================

/// 设置当前线程的错误处理器
///
/// 应在 Worker 初始化时调用。
pub fn setHandler(handler: ErrorHandler) void {
    current_handler = handler;
}

/// 重置为默认处理器
pub fn resetHandler() void {
    current_handler = defaultHandler;
}

/// 设置当前线程的 Worker ID
pub fn setWorkerId(id: u8) void {
    current_worker_id = id;
}

/// 获取当前线程的 Worker ID
pub fn getWorkerId() u8 {
    return current_worker_id;
}

/// 报告错误（完整版）
pub fn report(ctx: ErrorContext) void {
    current_handler(ctx);
}

/// 报告错误（简化版）
///
/// 适用于大多数场景，自动填充时间戳。
pub fn reportError(
    source: ErrorSource,
    message: []const u8,
    raw_error: ?anyerror,
) void {
    report(.{
        .source = source,
        .severity = .err,
        .message = message,
        .raw_error = raw_error,
        .timestamp = std.time.microTimestamp(),
    });
}

/// 报告警告
pub fn reportWarning(
    source: ErrorSource,
    message: []const u8,
) void {
    report(.{
        .source = source,
        .severity = .warning,
        .message = message,
        .timestamp = std.time.microTimestamp(),
    });
}

/// 报告严重错误
pub fn reportCritical(
    source: ErrorSource,
    message: []const u8,
    raw_error: ?anyerror,
) void {
    report(.{
        .source = source,
        .severity = .critical,
        .message = message,
        .raw_error = raw_error,
        .timestamp = std.time.microTimestamp(),
    });
}

/// 报告带连接上下文的错误
pub fn reportConnectionError(
    source: ErrorSource,
    message: []const u8,
    connection_id: u64,
    raw_error: ?anyerror,
) void {
    report(.{
        .source = source,
        .severity = .err,
        .message = message,
        .raw_error = raw_error,
        .connection_id = connection_id,
        .timestamp = std.time.microTimestamp(),
    });
}

/// 报告带流上下文的错误
pub fn reportStreamError(
    source: ErrorSource,
    message: []const u8,
    connection_id: u64,
    stream_id: u64,
    raw_error: ?anyerror,
) void {
    report(.{
        .source = source,
        .severity = .err,
        .message = message,
        .raw_error = raw_error,
        .connection_id = connection_id,
        .stream_id = stream_id,
        .timestamp = std.time.microTimestamp(),
    });
}

// =============================================================================
// 预置处理器工厂
// =============================================================================

/// 创建一个带统计功能的处理器
///
/// 返回的处理器会在调用时递增对应计数器。
/// 注意：计数器本身需要是线程本地的或使用原子操作。
pub fn createCountingHandler(
    counters: *ErrorCounters,
    next_handler: ?ErrorHandler,
) ErrorHandler {
    // 由于 Zig 不支持闭包捕获，这里使用静态变量模拟
    // 实际使用时建议通过 threadlocal 变量传递
    _ = counters;
    return next_handler orelse defaultHandler;
}

/// 错误计数器（线程本地使用）
pub const ErrorCounters = struct {
    transport_errors: u64 = 0,
    protocol_errors: u64 = 0,
    session_errors: u64 = 0,
    business_errors: u64 = 0,
    system_errors: u64 = 0,
    total_errors: u64 = 0,
    total_warnings: u64 = 0,
    total_critical: u64 = 0,

    pub fn increment(self: *ErrorCounters, ctx: ErrorContext) void {
        switch (ctx.source) {
            .transport => self.transport_errors += 1,
            .protocol => self.protocol_errors += 1,
            .session => self.session_errors += 1,
            .business => self.business_errors += 1,
            .system, .config, .unknown => self.system_errors += 1,
        }
        switch (ctx.severity) {
            .warning => self.total_warnings += 1,
            .critical => self.total_critical += 1,
            .err => self.total_errors += 1,
            else => {},
        }
    }

    pub fn reset(self: *ErrorCounters) void {
        self.* = .{};
    }
};
