//! IPv4 NAT packet rewriting. Checksums are recomputed from scratch: NAT
//! mutations are rare per flow and correctness matters more than the
//! incremental RFC 1624 optimization (which can land later).

const std = @import("std");
const types = @import("../types.zig");
const ipv4 = @import("../l3/ipv4.zig");
const icmp = @import("../l3/icmp.zig");

pub const Rule = struct {
    port: types.PortId,
    addr: types.Ipv4,
};

pub fn rewriteSource(packet: []u8, addr: types.Ipv4, port: u16) bool {
    return rewrite(packet, addr, null, port, null);
}

pub fn rewriteDestination(packet: []u8, addr: types.Ipv4, port: u16) bool {
    return rewrite(packet, null, addr, null, port);
}

fn rewrite(
    packet: []u8,
    new_src: ?types.Ipv4,
    new_dst: ?types.Ipv4,
    new_sport: ?u16,
    new_dport: ?u16,
) bool {
    const header = ipv4.parse(packet) catch return false;
    if (header.isFragment()) return false;
    if (header.total_len > packet.len) return false;

    if (new_src) |addr| {
        std.mem.writeInt(u32, packet[12..16], addr.value, .big);
    }
    if (new_dst) |addr| {
        std.mem.writeInt(u32, packet[16..20], addr.value, .big);
    }

    const payload = packet[header.header_len..header.total_len];
    switch (header.protocol) {
        ipv4.Protocol.tcp => {
            if (payload.len < 20) return false;
            if (new_sport) |port| writeU16(payload, 0, port);
            if (new_dport) |port| writeU16(payload, 2, port);
            writeU16(payload, 16, 0);
            writeU16(payload, 16, transportChecksum(
                readIp(packet, 12),
                readIp(packet, 16),
                header.protocol,
                payload,
            ));
        },
        ipv4.Protocol.udp => {
            if (payload.len < 8) return false;
            const udp_len = readU16(payload, 4);
            if (udp_len < 8 or udp_len > payload.len) return false;
            if (new_sport) |port| writeU16(payload, 0, port);
            if (new_dport) |port| writeU16(payload, 2, port);
            if (readU16(payload, 6) != 0) {
                writeU16(payload, 6, 0);
                var sum = transportChecksum(
                    readIp(packet, 12),
                    readIp(packet, 16),
                    header.protocol,
                    payload[0..udp_len],
                );
                if (sum == 0) sum = 0xffff;
                writeU16(payload, 6, sum);
            }
        },
        ipv4.Protocol.icmp => {
            if (payload.len < 8) return false;
            if (payload[0] != icmp.Type.echo_request and payload[0] != icmp.Type.echo_reply) {
                return false;
            }
            if (new_sport orelse new_dport) |id| writeU16(payload, 4, id);
            writeU16(payload, 2, 0);
            writeU16(payload, 2, ipv4.checksum(payload));
        },
        else => {},
    }

    writeU16(packet, 10, 0);
    writeU16(packet, 10, ipv4.checksum(packet[0..header.header_len]));
    return true;
}

fn transportChecksum(
    src: types.Ipv4,
    dst: types.Ipv4,
    protocol: u8,
    data: []const u8,
) u16 {
    var sum: u32 = 0;
    sum += (src.value >> 16) & 0xffff;
    sum += src.value & 0xffff;
    sum += (dst.value >> 16) & 0xffff;
    sum += dst.value & 0xffff;
    sum += protocol;
    sum += @intCast(data.len);

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) sum += readU16(data, i);
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

fn readIp(packet: []const u8, offset: usize) types.Ipv4 {
    return .{ .value = std.mem.readInt(u32, packet[offset..][0..4], .big) };
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

const testing = std.testing;

fn testIp(s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

fn buildUdp(buf: []u8, src: types.Ipv4, dst: types.Ipv4, sport: u16, dport: u16, payload: []const u8) ![]u8 {
    var udp_buf: [512]u8 = undefined;
    const udp_len = 8 + payload.len;
    writeU16(&udp_buf, 0, sport);
    writeU16(&udp_buf, 2, dport);
    writeU16(&udp_buf, 4, @intCast(udp_len));
    writeU16(&udp_buf, 6, 0);
    @memcpy(udp_buf[8..udp_len], payload);

    const ip_len = try ipv4.write(buf, src, dst, ipv4.Protocol.udp, 64, 1, udp_buf[0..udp_len]);
    return buf[0..ip_len];
}

test "rewrites udp source and destination" {
    var buf: [512]u8 = undefined;
    var packet = try buildUdp(
        &buf,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        40000,
        9999,
        "hello",
    );

    try testing.expect(rewriteSource(packet, testIp("10.0.2.1"), 40001));
    const out = try ipv4.parse(packet);
    try testing.expect(out.src.eql(testIp("10.0.2.1")));
    try testing.expect(out.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 40001), readU16(out.payload, 0));
    try testing.expectEqual(@as(u16, 9999), readU16(out.payload, 2));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(packet[0..out.header_len]));
    try testing.expectEqual(@as(u16, 0), readU16(out.payload, 6));

    try testing.expect(rewriteDestination(packet, testIp("10.0.1.9"), 1234));
    const back = try ipv4.parse(packet);
    try testing.expect(back.dst.eql(testIp("10.0.1.9")));
    try testing.expectEqual(@as(u16, 1234), readU16(back.payload, 2));
}

test "rewrites icmp echo id and checksum" {
    var icmp_buf: [64]u8 = undefined;
    const icmp_len = try icmp.writeEchoRequest(&icmp_buf, 0x1234, 1, "ping");
    var buf: [128]u8 = undefined;
    const ip_len = try ipv4.write(
        &buf,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        ipv4.Protocol.icmp,
        64,
        7,
        icmp_buf[0..icmp_len],
    );
    const packet = buf[0..ip_len];

    try testing.expect(rewriteSource(packet, testIp("10.0.2.1"), 0x4321));
    const out = try ipv4.parse(packet);
    try testing.expect(out.src.eql(testIp("10.0.2.1")));
    try testing.expectEqual(@as(u16, 0x4321), readU16(out.payload, 4));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(out.payload));
}
