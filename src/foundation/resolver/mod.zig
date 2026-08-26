//! 异步 DNS 解析组件
//!
//! 本文件定义稳定的 Resolver 接口（vtable + 类型擦除），并把 c-ares 实现作为
//! resolver.Cares 一并导出，使用方只依赖本 mod.zig 即可拿到接口与默认实现。

const std = @import("std");
const foundation = @import("../mod.zig");
const net = foundation.net;

/// c-ares 异步 DNS 解析实现。
pub const Cares = @import("cares.zig").CaresResolver;

pub const ResolveError = error{
    InvalidHost,
    NoAddress,
    ResolverFailed,
    Timeout,
    Canceled,
    OutOfMemory,
};

pub const ResolveResult = union(enum) {
    address: net.Address,
    err: ResolveError,
};

pub const ResolveCallback = *const fn (ctx: ?*anyopaque, result: ResolveResult) void;

pub const ResolveHandle = struct {
    id: u64,
};

pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        resolve: *const fn (
            ptr: *anyopaque,
            host: []const u8,
            port: u16,
            callback: ResolveCallback,
            ctx: ?*anyopaque,
        ) ResolveError!ResolveHandle,
        cancel: *const fn (ptr: *anyopaque, handle: ResolveHandle) void,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn init(comptime T: type, impl: *T) Resolver {
        const gen = struct {
            fn resolve(
                ptr: *anyopaque,
                host: []const u8,
                port: u16,
                callback: ResolveCallback,
                ctx: ?*anyopaque,
            ) ResolveError!ResolveHandle {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self.resolve(host, port, callback, ctx);
            }

            fn cancel(ptr: *anyopaque, handle: ResolveHandle) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                self.cancel(handle);
            }

            fn deinit(ptr: *anyopaque) void {
                const self: *T = @ptrCast(@alignCast(ptr));
                self.deinit();
            }
        };

        return .{
            .ptr = impl,
            .vtable = &.{
                .resolve = gen.resolve,
                .cancel = gen.cancel,
                .deinit = gen.deinit,
            },
        };
    }

    pub fn resolve(
        self: Resolver,
        host: []const u8,
        port: u16,
        callback: ResolveCallback,
        ctx: ?*anyopaque,
    ) ResolveError!ResolveHandle {
        return self.vtable.resolve(self.ptr, host, port, callback, ctx);
    }

    pub fn cancel(self: Resolver, handle: ResolveHandle) void {
        self.vtable.cancel(self.ptr, handle);
    }

    pub fn deinit(self: Resolver) void {
        self.vtable.deinit(self.ptr);
    }
};
