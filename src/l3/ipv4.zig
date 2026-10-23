//! IPv4 header parsing and construction (RFC 791), with strict length and
//! checksum validation. Options are skipped but counted in `header_len`;
//! fragments are surfaced so callers can apply the no-L4-inspection rule.

const std = @import("std");
const types = @import("../types.zig");

pub const Protocol = struct {
    pub const icmp: u8 = 1;
    pub const tcp: u8 = 6;
    pub const udp: u8 = 17;
};

pub const Error = error{
    Truncated,
    NotIpv4,
    BadHeaderLength,
    BadTotalLength,
    BadChecksum,
    TtlExpired,
    TooLarge,
    NoSpace,
};

pub const Header = struct {
    header_len: u8,
    total_len: u16,
    id: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    payload: []const u8,
    packet: []const u8,

    pub fn fragmentOffset(self: Header) u16 {
        return self.flags_frag & 0x1fff;
    }

    pub fn moreFragments(self: Header) bool {
        return self.flags_frag & 0x2000 != 0;
    }

    pub fn dontFragment(self: Header) bool {
        return self.flags_frag & 0x4000 != 0;
    }

    pub fn isFragment(self: Header) bool {
        return self.moreFragments() or self.fragmentOffset() != 0;
    }
};

pub fn parse(packet: []const u8) Error!Header {
    if (packet.len < 20) return error.Truncated;

    const version = packet[0] >> 4;
    const ihl = packet[0] & 0x0f;
    if (version != 4) return error.NotIpv4;
    if (ihl < 5) return error.BadHeaderLength;

    const header_len: usize = @as(usize, ihl) * 4;
    if (packet.len < header_len) return error.Truncated;

    const total_len: usize = readU16(packet, 2);
    if (total_len < header_len) return error.BadTotalLength;
    if (total_len > packet.len) return error.BadTotalLength;
    if (checksum(packet[0..header_len]) != 0) return error.BadChecksum;

    return .{
        .header_len = @intCast(header_len),
        .total_len = @intCast(total_len),
        .id = readU16(packet, 4),
        .flags_frag = readU16(packet, 6),
        .ttl = packet[8],
        .protocol = packet[9],
        .src = .{ .value = readU32(packet, 12) },
        .dst = .{ .value = readU32(packet, 16) },
        .payload = packet[header_len..total_len],
        .packet = packet[0..total_len],
    };
}

pub fn write(
    buf: []u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    protocol: u8,
    ttl: u8,
    id: u16,
    payload: []const u8,
) Error!usize {
    return writeFlags(buf, src, dst, protocol, ttl, id, 0, payload);
}

pub fn writeFlags(
    buf: []u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    protocol: u8,
    ttl: u8,
    id: u16,
    flags_frag: u16,
    payload: []const u8,
) Error!usize {
    const total = 20 + payload.len;
    if (total > 65535) return error.TooLarge;
    if (buf.len < total) return error.NoSpace;

    @memset(buf[0..20], 0);
    buf[0] = 0x45;
    writeU16(buf, 2, @intCast(total));
    writeU16(buf, 4, id);
    writeU16(buf, 6, flags_frag);
    buf[8] = ttl;
    buf[9] = protocol;
    writeU32(buf, 12, src.value);
    writeU32(buf, 16, dst.value);
    @memcpy(buf[20..total], payload);
    writeU16(buf, 10, checksum(buf[0..20]));
    return total;
}

pub fn checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += readU16(data, i);
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @truncate(~sum);
}

/// Decrements TTL and recomputes the header checksum in place.
pub fn decrementTtl(packet: []u8) Error!void {
    const header = try parse(packet);
    if (header.ttl <= 1) return error.TtlExpired;

    packet[8] -= 1;
    writeU16(packet, 10, 0);
    writeU16(packet, 10, checksum(packet[0..header.header_len]));
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn readU32(buf: []const u8, off: usize) u32 {
    return (@as(u32, buf[off]) << 24) |
        (@as(u32, buf[off + 1]) << 16) |
        (@as(u32, buf[off + 2]) << 8) |
        buf[off + 3];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

fn writeU32(buf: []u8, off: usize, value: u32) void {
    buf[off] = @truncate(value >> 24);
    buf[off + 1] = @truncate(value >> 16);
    buf[off + 2] = @truncate(value >> 8);
    buf[off + 3] = @truncate(value);
}

const testing = std.testing;

fn testSrc() types.Ipv4 {
    return types.Ipv4.parse("10.0.1.2") catch unreachable;
}
fn testDst() types.Ipv4 {
    return types.Ipv4.parse("10.0.2.2") catch unreachable;
}

test "ipv4 build and parse" {
    var packet: [64]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.icmp, 64, 0x1234, "hello");
    const h = try parse(packet[0..n]);

    try testing.expectEqual(@as(u8, 20), h.header_len);
    try testing.expectEqual(@as(u16, 25), h.total_len);
    try testing.expectEqual(@as(u16, 0x1234), h.id);
    try testing.expectEqual(@as(u8, 64), h.ttl);
    try testing.expectEqual(Protocol.icmp, h.protocol);
    try testing.expect(h.src.eql(testSrc()));
    try testing.expect(h.dst.eql(testDst()));
    try testing.expectEqualSlices(u8, "hello", h.payload);
    try testing.expectEqual(@as(u16, 0), checksum(packet[0..20]));
}

test "ipv4 rejects malformed headers" {
    var packet: [32]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.icmp, 64, 1, "hello");
    try testing.expect(n > 20);

    var bad = packet;
    bad[0] = 0x65;
    try testing.expectError(error.NotIpv4, parse(&bad));

    bad = packet;
    bad[0] = 0x44;
    try testing.expectError(error.BadHeaderLength, parse(&bad));

    bad = packet;
    writeU16(&bad, 2, 10);
    try testing.expectError(error.BadTotalLength, parse(&bad));

    bad = packet;
    bad[10] ^= 0xff;
    try testing.expectError(error.BadChecksum, parse(&bad));

    try testing.expectError(error.Truncated, parse(packet[0..19]));
}

test "ipv4 rejects total length beyond buffer" {
    var packet: [32]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.icmp, 64, 1, "hello");
    writeU16(&packet, 2, @intCast(n + 1));
    writeU16(&packet, 10, 0);
    writeU16(&packet, 10, checksum(packet[0..20]));
    try testing.expectError(error.BadTotalLength, parse(packet[0..n]));
}

test "ipv4 fragmentation flags" {
    var packet: [32]u8 = undefined;
    const n = try writeFlags(&packet, testSrc(), testDst(), Protocol.udp, 64, 7, 0x2001, "frag");
    const h = try parse(packet[0..n]);

    try testing.expect(h.moreFragments());
    try testing.expectEqual(@as(u16, 1), h.fragmentOffset());
    try testing.expect(h.isFragment());
    try testing.expect(!h.dontFragment());
}

test "ipv4 ttl decrement updates checksum" {
    var packet: [32]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.icmp, 64, 9, "ping");
    try decrementTtl(packet[0..n]);

    const h = try parse(packet[0..n]);
    try testing.expectEqual(@as(u8, 63), h.ttl);
    try testing.expectEqualSlices(u8, "ping", h.payload);
}

test "ipv4 ttl expiry is rejected" {
    var packet: [32]u8 = undefined;
    const n = try write(&packet, testSrc(), testDst(), Protocol.icmp, 1, 9, "ping");
    try testing.expectError(error.TtlExpired, decrementTtl(packet[0..n]));
}

test "ipv4 checksum is ones-complement" {
    var header: [20]u8 = @splat(0);
    header[0] = 0x45;
    writeU16(&header, 2, 20);
    writeU16(&header, 4, 0x1234);
    header[8] = 64;
    header[9] = Protocol.icmp;
    writeU32(&header, 12, testSrc().value);
    writeU32(&header, 16, testDst().value);
    writeU16(&header, 10, checksum(&header));
    try testing.expectEqual(@as(u16, 0), checksum(&header));
}
