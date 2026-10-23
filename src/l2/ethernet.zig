//! Ethernet II framing (RFC 894 as used by 802.3), including a single 802.1Q
//! tag. VLAN bridging itself is a later milestone; the parser exposes the tag
//! so the forwarding decision can reject or account for it explicitly.

const std = @import("std");
const types = @import("../types.zig");

pub const EtherType = struct {
    pub const ipv4: u16 = 0x0800;
    pub const arp: u16 = 0x0806;
    pub const ipv6: u16 = 0x86dd;
    pub const vlan: u16 = 0x8100;
};

pub const Error = error{
    Truncated,
    NoSpace,
    UnsupportedVlanStack,
};

pub const Header = struct {
    dst: types.Mac,
    src: types.Mac,
    ethertype: u16,
    vlan: ?u16,
    header_len: u8,
    payload: []const u8,
};

pub fn parse(frame: []const u8) Error!Header {
    if (frame.len < 14) return error.Truncated;

    var ethertype = readU16(frame, 12);
    var vlan: ?u16 = null;
    var header_len: usize = 14;

    if (ethertype == EtherType.vlan) {
        if (frame.len < 18) return error.Truncated;
        const tci = readU16(frame, 14);
        vlan = tci & 0x0fff;
        ethertype = readU16(frame, 16);
        header_len = 18;
        if (ethertype == EtherType.vlan) return error.UnsupportedVlanStack;
    }

    return .{
        .dst = .{ .bytes = frame[0..6].* },
        .src = .{ .bytes = frame[6..12].* },
        .ethertype = ethertype,
        .vlan = vlan,
        .header_len = @intCast(header_len),
        .payload = frame[header_len..],
    };
}

pub fn write(
    buf: []u8,
    dst: types.Mac,
    src: types.Mac,
    ethertype: u16,
    vlan: ?u16,
) Error!usize {
    const need: usize = if (vlan != null) 18 else 14;
    if (buf.len < need) return error.NoSpace;

    @memcpy(buf[0..6], &dst.bytes);
    @memcpy(buf[6..12], &src.bytes);

    var off: usize = 12;
    if (vlan) |vid| {
        writeU16(buf, off, EtherType.vlan);
        writeU16(buf, off + 2, vid & 0x0fff);
        off += 4;
    }
    writeU16(buf, off, ethertype);
    return need;
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

const testing = std.testing;

const mac_a: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0a } };
const mac_b: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0b } };

test "ethernet parse untagged" {
    var frame: [64]u8 = undefined;
    const hlen = try write(&frame, mac_a, mac_b, EtherType.ipv4, null);
    try testing.expectEqual(@as(usize, 14), hlen);
    frame[14] = 0x45;

    const h = try parse(frame[0 .. hlen + 1]);
    try testing.expect(h.dst.eql(mac_a));
    try testing.expect(h.src.eql(mac_b));
    try testing.expectEqual(EtherType.ipv4, h.ethertype);
    try testing.expectEqual(@as(?u16, null), h.vlan);
    try testing.expectEqual(@as(u8, 14), h.header_len);
    try testing.expectEqualSlices(u8, &.{0x45}, h.payload);
}

test "ethernet parse vlan tag" {
    var frame: [64]u8 = undefined;
    const hlen = try write(&frame, mac_a, mac_b, EtherType.arp, 100);
    try testing.expectEqual(@as(usize, 18), hlen);
    frame[18] = 0x00;
    frame[19] = 0x01;

    const h = try parse(frame[0..20]);
    try testing.expectEqual(@as(?u16, 100), h.vlan);
    try testing.expectEqual(EtherType.arp, h.ethertype);
    try testing.expectEqual(@as(u8, 18), h.header_len);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, h.payload);
}

test "ethernet rejects truncated frames" {
    try testing.expectError(error.Truncated, parse(&.{}));
    try testing.expectError(error.Truncated, parse(&@as([13]u8, @splat(0))));

    var tagged: [18]u8 = undefined;
    _ = try write(&tagged, mac_a, mac_b, EtherType.ipv4, 1);
    try testing.expectError(error.Truncated, parse(tagged[0..17]));
}

test "ethernet rejects stacked vlan tags" {
    var frame: [18]u8 = undefined;
    _ = try write(&frame, mac_a, mac_b, EtherType.vlan, 1);
    try testing.expectError(error.UnsupportedVlanStack, parse(&frame));
}

test "ethernet write enforces space" {
    var small: [10]u8 = undefined;
    try testing.expectError(error.NoSpace, write(&small, mac_a, mac_b, EtherType.ipv4, null));
}

test "ethernet broadcast and multicast helpers" {
    try testing.expect(types.Mac.broadcast.isBroadcast());
    try testing.expect(types.Mac.broadcast.isMulticast());
    try testing.expect(!mac_a.isMulticast());
}
