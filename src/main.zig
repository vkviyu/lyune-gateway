const std = @import("std");
const xev = @import("xev");
const builtin = @import("builtin");

pub fn main() !void {
    // 1. 初始化 Loop
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    // 2. 声明 Completion (完成器)
    // 修正点：
    // A. 使用 var (因为 loop 需要修改它的内部状态)
    // B. 使用 undefined (因为它只是一个结果容器，马上就会被 loop 使用，不需要初始化值)
    var c: xev.Completion = undefined;

    // 3. 打印当前后端信息
    std.debug.print("Lyune Gateway is running on OS: {s}\n", .{@tagName(builtin.os.tag)});

    // 4. 我们来做一个真正的操作：比如等待 1 毫秒的定时器
    // 这样能证明 completion 真的能用
    std.debug.print("Starting a 1ms timer...\n", .{});

    // 发起异步定时器操作
    // 参数含义：
    // - &c: 我们刚才定义的 completion 的指针
    // - 1: 毫秒数
    // - null: 用户数据 (userdata)，这里不需要
    // - 回调函数
    loop.timer(&c, 1, null, (struct {
        fn callback(
            _: ?*anyopaque, // userdata
            _: *xev.Loop, // loop
            _: *xev.Completion, // completion
            r: xev.Result, // result
        ) xev.CallbackAction {
            std.debug.print("Timer fired! Result: {}\n", .{r});
            return .disarm; // 任务完成，解除武装
        }
    }.callback));

    // 5. 运行循环
    // .until_done 表示运行直到所有任务完成（这里就是定时器触发后）
    try loop.run(.until_done);

    std.debug.print("Loop finished.\n", .{});
}
