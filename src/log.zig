//! Leveled logging.
//!
//! Never log packet payloads, keys or tokens above `debug` (AGENTS.md rule 9).
//! Formatting uses a fixed stack buffer: the hot path must not allocate.

const std = @import("std");
const schema = @import("config/schema.zig");

pub const Level = schema.LogLevel;

pub const Logger = struct {
    io: std.Io,
    level: Level = .info,
    format: schema.LogFormat = .text,
    file: std.Io.File = std.Io.File.stderr(),

    pub fn init(io: std.Io, cfg: schema.LogConfig) Logger {
        return .{ .io = io, .level = cfg.level, .format = cfg.format };
    }

    pub fn enabled(self: *const Logger, level: Level) bool {
        return @intFromEnum(level) >= @intFromEnum(self.level);
    }

    pub fn log(self: *const Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (!self.enabled(level)) return;

        var msg_buf: [768]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch "<message too long>";

        var line_buf: [1024]u8 = undefined;
        const line = self.formatLine(level, msg, &line_buf);
        self.file.writeStreamingAll(self.io, line) catch {};
    }

    pub fn debug(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn warn(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, fmt, args);
    }

    pub fn err(self: *const Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    /// Renders one line into `out` and returns the written slice. Truncates on
    /// overflow; logging must never fail or panic.
    pub fn formatLine(self: *const Logger, level: Level, msg: []const u8, out: []u8) []const u8 {
        var pos: usize = 0;
        if (self.format == .json) {
            append(out, &pos, "{\"level\":\"");
            append(out, &pos, levelName(level));
            append(out, &pos, "\",\"msg\":\"");
            appendJsonEscaped(out, &pos, msg);
            append(out, &pos, "\"}\n");
        } else {
            append(out, &pos, "[");
            append(out, &pos, levelName(level));
            append(out, &pos, "] ");
            append(out, &pos, msg);
            append(out, &pos, "\n");
        }
        return out[0..pos];
    }
};

fn levelName(level: Level) []const u8 {
    return switch (level) {
        .debug => "debug",
        .info => "info",
        .warn => "warn",
        .err => "error",
    };
}

fn append(out: []u8, pos: *usize, text: []const u8) void {
    if (pos.* + text.len > out.len) return;
    @memcpy(out[pos.*..][0..text.len], text);
    pos.* += text.len;
}

fn appendJsonEscaped(out: []u8, pos: *usize, text: []const u8) void {
    const hex = "0123456789abcdef";
    for (text) |c| {
        const escaped: ?[]const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            else => null,
        };
        if (escaped) |e| {
            append(out, pos, e);
            continue;
        }
        if (c < 0x20) {
            if (pos.* + 6 > out.len) return;
            out[pos.*] = '\\';
            out[pos.* + 1] = 'u';
            out[pos.* + 2] = '0';
            out[pos.* + 3] = '0';
            out[pos.* + 4] = hex[c >> 4];
            out[pos.* + 5] = hex[c & 0x0f];
            pos.* += 6;
            continue;
        }
        if (pos.* >= out.len) return;
        out[pos.*] = c;
        pos.* += 1;
    }
}

test "level filtering" {
    var logger = Logger{ .io = std.testing.io, .level = .warn };
    try std.testing.expect(!logger.enabled(.debug));
    try std.testing.expect(!logger.enabled(.info));
    try std.testing.expect(logger.enabled(.warn));
    try std.testing.expect(logger.enabled(.err));
}

test "text line" {
    const logger = Logger{ .io = std.testing.io, .format = .text };
    var buf: [128]u8 = undefined;
    const line = logger.formatLine(.info, "hello", &buf);
    try std.testing.expectEqualStrings("[info] hello\n", line);
}

test "json line escapes control characters" {
    const logger = Logger{ .io = std.testing.io, .format = .json };
    var buf: [128]u8 = undefined;
    const line = logger.formatLine(.err, "a\"b\nc", &buf);
    try std.testing.expectEqualStrings(
        "{\"level\":\"error\",\"msg\":\"a\\\"b\\nc\"}\n",
        line,
    );
}

test "line truncates instead of failing" {
    const logger = Logger{ .io = std.testing.io, .format = .text };
    var buf: [4]u8 = undefined;
    const line = logger.formatLine(.info, "abcdef", &buf);
    try std.testing.expect(line.len <= buf.len);
}
