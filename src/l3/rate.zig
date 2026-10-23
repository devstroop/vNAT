//! Token buckets for control-plane policing. Time is monotonic milliseconds;
//! zero disables the limiter. Buckets hold one second of burst.

const std = @import("std");

pub const Limiter = struct {
    rate_per_sec: u32 = 0,
    tokens: u32 = 0,
    last_ms: i64 = -1,

    pub fn init(rate_per_sec: u32) Limiter {
        return .{ .rate_per_sec = rate_per_sec, .tokens = rate_per_sec };
    }

    pub fn allow(self: *Limiter, now_ms: i64) bool {
        if (self.rate_per_sec == 0) return true;
        if (self.last_ms < 0 or now_ms < self.last_ms) {
            self.last_ms = now_ms;
            self.tokens = self.rate_per_sec;
        } else {
            const elapsed: u64 = @intCast(now_ms - self.last_ms);
            if (elapsed >= 1000) {
                self.tokens = self.rate_per_sec;
                self.last_ms = now_ms;
            } else if (elapsed > 0) {
                const add = (elapsed * self.rate_per_sec) / 1000;
                if (add > 0) {
                    self.tokens = @intCast(@min(
                        @as(u64, self.rate_per_sec),
                        @as(u64, self.tokens) + add,
                    ));
                    // Keep the sub-token remainder so a slow stream is not
                    // starved by millisecond truncation.
                    self.last_ms += @intCast((add * 1000) / self.rate_per_sec);
                }
            }
        }
        if (self.tokens == 0) return false;
        self.tokens -= 1;
        return true;
    }
};

test "limiter allows a burst then refills" {
    var limiter = Limiter.init(2);
    try std.testing.expect(limiter.allow(1000));
    try std.testing.expect(limiter.allow(1000));
    try std.testing.expect(!limiter.allow(1000));
    try std.testing.expect(!limiter.allow(1499));
    try std.testing.expect(limiter.allow(1500));
    try std.testing.expect(!limiter.allow(1500));
}

test "limiter accumulates fractions across calls" {
    var limiter = Limiter.init(10);
    for (0..10) |_| try std.testing.expect(limiter.allow(0));
    try std.testing.expect(!limiter.allow(99));
    try std.testing.expect(limiter.allow(100));
    try std.testing.expect(!limiter.allow(100));
}

test "limiter zero is unlimited and clock reset is safe" {
    var unlimited = Limiter.init(0);
    try std.testing.expect(unlimited.allow(0));
    try std.testing.expect(unlimited.allow(0));

    var limiter = Limiter.init(1);
    try std.testing.expect(limiter.allow(100));
    try std.testing.expect(limiter.allow(50));
    try std.testing.expect(!limiter.allow(50));
}
