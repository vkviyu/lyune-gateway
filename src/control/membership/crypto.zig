//! membership 消息认证原语。
//!
//! HMAC-SHA256 只负责报文认证，不负责密钥派生、轮换或配置解析。
//! 上层必须对同一份完整线路字节计算和校验 MAC，并使用 constant-time 比较。

const std = @import("std");

pub const mac_size: usize = std.crypto.auth.hmac.sha2.HmacSha256.mac_length;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// 计算 HMAC-SHA256。
pub fn mac(key: []const u8, message: []const u8) [mac_size]u8 {
    var result: [mac_size]u8 = undefined;
    HmacSha256.create(&result, message, key);
    return result;
}

/// 使用 constant-time 比较校验 MAC。
pub fn verify(key: []const u8, message: []const u8, expected: *const [mac_size]u8) bool {
    const actual = mac(key, message);
    return std.crypto.timing_safe.eql([mac_size]u8, actual, expected.*);
}

test "HMAC-SHA256 matches RFC 4231 case 2" {
    const key = "Jefe";
    const message = "what do ya want for nothing?";
    const expected = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqual(expected, mac(key, message));
    try std.testing.expect(verify(key, message, &expected));
}
