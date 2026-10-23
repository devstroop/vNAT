//! 802.1D configuration BPDUs (RSTP is out of scope). Only the fields needed
//! for basic root election and forwarding-state convergence are exposed.

const std = @import("std");
const types = @import("../types.zig");

pub const multicast = types.Mac{ .bytes = .{ 0x01, 0x80, 0xc2, 0, 0, 0 } };
pub const default_priority: u16 = 0x8000;
pub const default_port_cost: u32 = 19;
pub const hello_ms: u32 = 2000;
pub const max_age_ms: u32 = 20_000;
pub const forward_delay_ms: u32 = 15_000;

pub const flags_tc: u8 = 0x01;
pub const flags_tca: u8 = 0x80;

pub const Error = error{
    Truncated,
    Unsupported,
};

/// LLC (3) + configuration BPDU (35), used as the 802.3 length field.
pub const payload_len: usize = 38;
const bpdu_len = 35;

pub const Bpdu = struct {
    flags: u8 = 0,
    root_id: u64 = 0,
    root_cost: u32 = 0,
    bridge_id: u64 = 0,
    port_id: u16 = 0,
    message_age_ms: u32 = 0,
    max_age_ms: u32 = max_age_ms,
    hello_ms: u32 = hello_ms,
    forward_delay_ms: u32 = forward_delay_ms,
};

pub fn write(buf: []u8, bpdu: Bpdu) Error!usize {
    if (buf.len < payload_len) return error.Truncated;
    buf[0] = 0x42;
    buf[1] = 0x42;
    buf[2] = 0x03;
    writeU16(buf, 3, 0);
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = bpdu.flags;
    writeId(buf, 8, bpdu.root_id);
    writeU32(buf, 16, bpdu.root_cost);
    writeId(buf, 20, bpdu.bridge_id);
    writeU16(buf, 28, bpdu.port_id);
    writeU16(buf, 30, ageToWire(bpdu.message_age_ms));
    writeU16(buf, 32, ageToWire(bpdu.max_age_ms));
    writeU16(buf, 34, ageToWire(bpdu.hello_ms));
    writeU16(buf, 36, ageToWire(bpdu.forward_delay_ms));
    return payload_len;
}

pub fn parse(payload: []const u8) Error!Bpdu {
    if (payload.len < payload_len) return error.Truncated;
    if (payload[0] != 0x42 or payload[1] != 0x42 or payload[2] != 0x03) {
        return error.Unsupported;
    }
    if (readU16(payload, 3) != 0 or payload[5] != 0 or payload[6] != 0) {
        return error.Unsupported;
    }
    return .{
        .flags = payload[7],
        .root_id = readId(payload, 8),
        .root_cost = readU32(payload, 16),
        .bridge_id = readId(payload, 20),
        .port_id = readU16(payload, 28),
        .message_age_ms = ageFromWire(readU16(payload, 30)),
        .max_age_ms = ageFromWire(readU16(payload, 32)),
        .hello_ms = ageFromWire(readU16(payload, 34)),
        .forward_delay_ms = ageFromWire(readU16(payload, 36)),
    };
}

pub fn bridgeId(priority: u16, mac: types.Mac) u64 {
    return (@as(u64, priority) << 48) | macToInt(mac);
}

pub fn idMac(id: u64) types.Mac {
    var mac = types.Mac{};
    var value = id;
    var i: usize = 6;
    while (i > 0) {
        i -= 1;
        mac.bytes[i] = @truncate(value);
        value >>= 8;
    }
    return mac;
}

pub fn idPriority(id: u64) u16 {
    return @truncate(id >> 48);
}

pub fn macToInt(mac: types.Mac) u64 {
    var value: u64 = 0;
    for (mac.bytes) |byte| value = (value << 8) | byte;
    return value;
}

/// True when `a` is a better spanning-tree vector than `b`.
pub fn vectorLess(
    root_a: u64,
    cost_a: u32,
    bridge_a: u64,
    port_a: u16,
    root_b: u64,
    cost_b: u32,
    bridge_b: u64,
    port_b: u16,
) bool {
    if (root_a != root_b) return root_a < root_b;
    if (cost_a != cost_b) return cost_a < cost_b;
    if (bridge_a != bridge_b) return bridge_a < bridge_b;
    return port_a < port_b;
}

fn ageToWire(ms: u32) u16 {
    const ticks = (@as(u64, ms) * 256) / 1000;
    return @intCast(@min(ticks, std.math.maxInt(u16)));
}

fn ageFromWire(value: u16) u32 {
    return (@as(u32, value) * 1000) / 256;
}

fn writeId(buf: []u8, off: usize, id: u64) void {
    writeU16(buf, off, @truncate(id >> 48));
    const mac = idMac(id);
    @memcpy(buf[off + 2 ..][0..6], &mac.bytes);
}

fn readId(buf: []const u8, off: usize) u64 {
    return (@as(u64, readU16(buf, off)) << 48) | macToInt(.{ .bytes = buf[off + 2 ..][0..6].* });
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

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn readU32(buf: []const u8, off: usize) u32 {
    return (@as(u32, buf[off]) << 24) |
        (@as(u32, buf[off + 1]) << 16) |
        (@as(u32, buf[off + 2]) << 8) |
        buf[off + 3];
}

test "bpdu round trip" {
    var buf: [payload_len]u8 = undefined;
    const root = bridgeId(0x8000, .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } });
    const bridge = bridgeId(0x8000, .{ .bytes = .{ 0x02, 0, 0, 0, 0, 2 } });
    const n = try write(&buf, .{
        .flags = flags_tc,
        .root_id = root,
        .root_cost = 19,
        .bridge_id = bridge,
        .port_id = 0x0100,
        .message_age_ms = 1234,
        .max_age_ms = max_age_ms,
    });
    try std.testing.expectEqual(payload_len, n);
    const parsed = try parse(&buf);
    try std.testing.expectEqual(flags_tc, parsed.flags);
    try std.testing.expectEqual(root, parsed.root_id);
    try std.testing.expectEqual(bridge, parsed.bridge_id);
    try std.testing.expectEqual(@as(u32, 19), parsed.root_cost);
    try std.testing.expectEqual(@as(u16, 0x0100), parsed.port_id);
    try std.testing.expectEqual(@as(u32, 1230), parsed.message_age_ms);
    try std.testing.expectEqual(@as(u32, max_age_ms), parsed.max_age_ms);
}

test "bpdu rejects malformed frames" {
    var buf: [payload_len]u8 = undefined;
    _ = try write(&buf, .{});
    try std.testing.expectError(error.Truncated, parse(buf[0 .. payload_len - 1]));
    buf[0] = 0;
    try std.testing.expectError(error.Unsupported, parse(&buf));
}

test "vector ordering" {
    try std.testing.expect(vectorLess(1, 100, 9, 1, 2, 0, 1, 1));
    try std.testing.expect(vectorLess(1, 10, 9, 1, 1, 20, 1, 1));
    try std.testing.expect(!vectorLess(1, 20, 1, 1, 1, 10, 9, 1));
}
