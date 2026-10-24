//! Deadline-bounded line reads for control clients. `std.Io` streams have no
//! read deadline, so poll() bounds a stalled peer like the DNS TCP worker.

const std = @import("std");

pub fn readLine(
    io: std.Io,
    fd: std.posix.fd_t,
    out: []u8,
    timeout_ms: u64,
) !?[]const u8 {
    const deadline = nowMs(io) + @as(i64, @intCast(@min(timeout_ms, std.math.maxInt(i64))));
    var used: usize = 0;
    while (used < out.len) {
        const remaining = deadline - nowMs(io);
        if (remaining <= 0) return error.Timeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&fds, @intCast(@min(remaining, std.math.maxInt(i32))));
        if (ready == 0) return error.Timeout;
        const n = std.posix.read(fd, out[used..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n == 0) return if (used == 0) null else error.EndOfStream;
        used += n;
        if (std.mem.indexOfScalar(u8, out[0..used], '\n')) |end| {
            return std.mem.trimEnd(u8, out[0..end], "\r");
        }
    }
    return error.LineTooLong;
}

pub fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.now(.awake, io).toMilliseconds();
}
