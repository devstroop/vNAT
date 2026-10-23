//! Golden-frame fixtures and helpers.
//!
//! Frames are stored as hex so tests read as byte-exact vectors. These are
//! structural vectors (checksums are zero); R2 adds checksum-valid vectors.

const std = @import("std");
const vnat = @import("../src/lib.zig");

/// Ethernet II + IPv4 + UDP: 10.0.0.1:1234 -> 10.0.0.2:5678.
pub const ipv4_udp =
    "ffffffffffff00112233445508004500001c00010000401100000a0000010a000002" ++
    "04d2162e00080000";

/// Same frame with an 802.1Q tag (VLAN 100).
pub const ipv4_udp_vlan =
    "ffffffffffff0011223344558100006408004500001c00010000401100000a000001" ++
    "0a00000204d2162e00080000";

pub fn decodeHex(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    const written = try std.fmt.hexToBytes(out, hex);
    if (written.len != out.len) return error.InvalidHex;
    return out;
}

pub fn expectEqualHex(expected_hex: []const u8, actual: []const u8) !void {
    const expected = try decodeHex(std.testing.allocator, expected_hex);
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, actual);
}

test "golden ethernet/ipv4/udp frame round-trips through the memory port" {
    const frame = try decodeHex(std.testing.allocator, ipv4_udp);
    defer std.testing.allocator.free(frame);

    var mp = vnat.MemoryPort.init(std.testing.allocator, .{ .value = 1 }, "golden0", 1500);
    defer mp.deinit();

    try mp.inject(frame);

    var buf: [2048]u8 = undefined;
    const n = (try mp.port().read(std.testing.io, &buf)).?;
    try expectEqualHex(ipv4_udp, buf[0..n]);
}

test "golden vlan frame round-trips" {
    const frame = try decodeHex(std.testing.allocator, ipv4_udp_vlan);
    defer std.testing.allocator.free(frame);
    try std.testing.expectEqual(@as(usize, 46), frame.len);

    var mp = vnat.MemoryPort.init(std.testing.allocator, .{ .value = 2 }, "golden1", 1500);
    defer mp.deinit();

    try mp.inject(frame);

    var buf: [2048]u8 = undefined;
    const n = (try mp.port().read(std.testing.io, &buf)).?;
    try expectEqualHex(ipv4_udp_vlan, buf[0..n]);
}

test "decodeHex rejects odd input" {
    try std.testing.expectError(error.InvalidHex, decodeHex(std.testing.allocator, "abc"));
}
