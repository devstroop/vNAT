//! I/O context helpers.
//!
//! Zig 0.16 requires an explicit `std.Io` for anything that blocks or is
//! nondeterministic. The core never creates a global instance; `main` owns it
//! and passes it down (see AGENTS.md rule 2).

const std = @import("std");

pub const Context = struct {
    io: std.Io,

    pub fn init(io: std.Io) Context {
        return .{ .io = io };
    }

    /// Monotonic-ish clock suitable for timeouts and stats. `awake` maps to
    /// CLOCK_MONOTONIC on Linux and CLOCK_UPTIME_RAW on macOS.
    pub fn now(self: Context) std.Io.Timestamp {
        return std.Io.Clock.now(.awake, self.io);
    }

    pub fn sleepMs(self: Context, ms: u64) !void {
        const duration = std.Io.Duration.fromMilliseconds(@intCast(ms));
        try std.Io.sleep(self.io, duration, .awake);
    }
};

test "duration milliseconds round-trip" {
    const d = std.Io.Duration.fromMilliseconds(250);
    try std.testing.expectEqual(@as(i64, 250), d.toMilliseconds());
}
