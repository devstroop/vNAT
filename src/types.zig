//! Core value types shared by the datapath and the control plane.
//!
//! All addresses are stored in host byte order as integers; conversion to and
//! from wire format is explicit via `toBytes`/`fromBytes`.

const std = @import("std");

pub const Mac = struct {
    bytes: [6]u8 = .{0} ** 6,

    pub const zero: Mac = .{};
    pub const broadcast: Mac = .{ .bytes = .{0xff} ** 6 };

    pub fn isZero(self: Mac) bool {
        for (self.bytes) |b| {
            if (b != 0) return false;
        }
        return true;
    }

    pub fn eql(a: Mac, b: Mac) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn isBroadcast(self: Mac) bool {
        return self.eql(broadcast);
    }

    pub fn isMulticast(self: Mac) bool {
        return self.bytes[0] & 1 != 0;
    }

    pub fn parse(s: []const u8) !Mac {
        var out: [6]u8 = undefined;
        var it = std.mem.splitAny(u8, s, ":-");
        var i: usize = 0;
        while (it.next()) |part| {
            if (i == 6 or part.len != 2) return error.InvalidMac;
            out[i] = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMac;
            i += 1;
        }
        if (i != 6) return error.InvalidMac;
        return .{ .bytes = out };
    }

    pub fn format(self: Mac, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5],
        });
    }
};

pub const Ipv4 = struct {
    /// Host-order integer. Network byte order is produced by `toBytes`.
    value: u32 = 0,

    pub const unspecified: Ipv4 = .{ .value = 0 };
    pub const limited_broadcast: Ipv4 = .{ .value = 0xffffffff };

    pub fn fromBytes(b: [4]u8) Ipv4 {
        return .{ .value = std.mem.readInt(u32, &b, .big) };
    }

    pub fn toBytes(self: Ipv4) [4]u8 {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, self.value, .big);
        return b;
    }

    pub fn parse(s: []const u8) !Ipv4 {
        var octets: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, s, '.');
        var i: usize = 0;
        while (it.next()) |part| {
            if (i == 4 or part.len == 0 or part.len > 3) return error.InvalidIpv4;
            octets[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4;
            i += 1;
        }
        if (i != 4) return error.InvalidIpv4;
        return fromBytes(octets);
    }

    pub fn eql(a: Ipv4, b: Ipv4) bool {
        return a.value == b.value;
    }

    pub fn isUnspecified(self: Ipv4) bool {
        return self.value == 0;
    }

    pub fn isMulticast(self: Ipv4) bool {
        return self.value & 0xf0000000 == 0xe0000000;
    }

    pub fn format(self: Ipv4, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const b = self.toBytes();
        try w.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
    }
};

pub const Prefix4 = struct {
    addr: Ipv4,
    len: u8,

    pub fn parse(s: []const u8) !Prefix4 {
        const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidPrefix;
        const addr = try Ipv4.parse(s[0..slash]);
        const len = std.fmt.parseInt(u8, s[slash + 1 ..], 10) catch return error.InvalidPrefix;
        if (len > 32) return error.InvalidPrefix;
        return .{ .addr = addr, .len = len };
    }

    pub fn mask(self: Prefix4) u32 {
        if (self.len == 0) return 0;
        const shift: u5 = @intCast(32 - self.len);
        return @as(u32, 0xffffffff) << shift;
    }

    pub fn network(self: Prefix4) Ipv4 {
        return .{ .value = self.addr.value & self.mask() };
    }

    pub fn contains(self: Prefix4, ip: Ipv4) bool {
        return (ip.value & self.mask()) == self.network().value;
    }

    pub fn eql(a: Prefix4, b: Prefix4) bool {
        return a.len == b.len and a.network().value == b.network().value;
    }

    pub fn format(self: Prefix4, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("{f}/{}", .{ self.addr, self.len });
    }
};

pub const IpPort = struct {
    ip: Ipv4,
    port: u16,
};

pub fn parseIpPort(s: []const u8) !IpPort {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidIpPort;
    if (colon == 0 or colon + 1 == s.len) return error.InvalidIpPort;
    const ip = try Ipv4.parse(s[0..colon]);
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.InvalidIpPort;
    if (port == 0) return error.InvalidIpPort;
    return .{ .ip = ip, .port = port };
}

pub const IpRange = struct {
    first: Ipv4,
    last: Ipv4,
};

pub fn parseIpRange(s: []const u8) !IpRange {
    const dash = std.mem.indexOfScalar(u8, s, '-') orelse return error.InvalidRange;
    const first = try Ipv4.parse(std.mem.trim(u8, s[0..dash], " \t"));
    const last = try Ipv4.parse(std.mem.trim(u8, s[dash + 1 ..], " \t"));
    if (first.value > last.value) return error.InvalidRange;
    return .{ .first = first, .last = last };
}

/// Parses `90`, `90s`, `30m`, `12h`, `7d` into seconds.
pub fn parseDurationSeconds(s: []const u8) !u32 {
    if (s.len == 0) return error.InvalidDuration;

    var n: u64 = 0;
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
        n = n * 10 + (s[i] - '0');
        if (n > std.math.maxInt(u32)) return error.InvalidDuration;
    }
    if (i == 0) return error.InvalidDuration;

    var mult: u64 = 1;
    if (i != s.len) {
        if (i + 1 != s.len) return error.InvalidDuration;
        mult = switch (s[i]) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            else => return error.InvalidDuration,
        };
    }

    const total = n * mult;
    if (total == 0 or total > std.math.maxInt(u32)) return error.InvalidDuration;
    return @intCast(total);
}

pub const PortId = struct {
    value: u32,

    pub const invalid: PortId = .{ .value = 0 };

    pub fn eql(a: PortId, b: PortId) bool {
        return a.value == b.value;
    }
};

pub const VlanId = struct {
    value: u12,

    pub const max: VlanId = .{ .value = 4094 };
};

test "mac parse and format" {
    const mac = try Mac.parse("aa:bb:cc:dd:ee:ff");
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &mac.bytes);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try out.writer.print("{f}", .{mac});
    try std.testing.expectEqualStrings("aa:bb:cc:dd:ee:ff", out.written());
}

test "ipv4 parse and format" {
    const ip = try Ipv4.parse("10.26.0.2");
    try std.testing.expectEqualSlices(u8, &.{ 10, 26, 0, 2 }, &ip.toBytes());

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try out.writer.print("{f}", .{ip});
    try std.testing.expectEqualStrings("10.26.0.2", out.written());
}

test "prefix network and containment" {
    const p = try Prefix4.parse("10.26.0.5/24");
    try std.testing.expectEqual(@as(u32, 0x0a1a0000), p.network().value);
    try std.testing.expect(p.contains(try Ipv4.parse("10.26.0.200")));
    try std.testing.expect(!p.contains(try Ipv4.parse("10.27.0.1")));
}

test "ip:port and ranges" {
    const hp = try parseIpPort("192.168.1.10:8080");
    try std.testing.expectEqual(@as(u16, 8080), hp.port);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &hp.ip.toBytes());

    const r = try parseIpRange("10.0.0.100-10.0.0.200");
    try std.testing.expect(r.first.value < r.last.value);
    try std.testing.expectError(error.InvalidRange, parseIpRange("10.0.0.200-10.0.0.100"));
}

test "duration parser" {
    try std.testing.expectEqual(@as(u32, 90), try parseDurationSeconds("90"));
    try std.testing.expectEqual(@as(u32, 30 * 60), try parseDurationSeconds("30m"));
    try std.testing.expectEqual(@as(u32, 12 * 3600), try parseDurationSeconds("12h"));
    try std.testing.expectEqual(@as(u32, 86400), try parseDurationSeconds("1d"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("0"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("12x"));
}
