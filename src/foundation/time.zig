const std = @import("std");

pub fn timestampSeconds() i64 {
    return std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toSeconds();
}

pub fn timestampMicros() i64 {
    return std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toMicroseconds();
}
