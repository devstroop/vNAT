//! ARP for Ethernet/IPv4 (RFC 826) and a small next-hop cache. The cache is
//! control-plane state: entries are populated from observed traffic and replies,
//! and the datapath only reads them.

const std = @import("std");
const types = @import("../types.zig");

pub const Error = error{
    Truncated,
    Unsupported,
    NoSpace,
};

pub const Operation = enum(u16) {
    request = 1,
    reply = 2,
};

pub const Packet = struct {
    operation: Operation,
    sender_mac: types.Mac,
    sender_ip: types.Ipv4,
    target_mac: types.Mac,
    target_ip: types.Ipv4,
};

pub fn parse(payload: []const u8) Error!Packet {
    if (payload.len < 28) return error.Truncated;
    if (readU16(payload, 0) != 1) return error.Unsupported;
    if (readU16(payload, 2) != 0x0800) return error.Unsupported;
    if (payload[4] != 6 or payload[5] != 4) return error.Unsupported;

    const operation: Operation = switch (readU16(payload, 6)) {
        1 => .request,
        2 => .reply,
        else => return error.Unsupported,
    };

    return .{
        .operation = operation,
        .sender_mac = .{ .bytes = payload[8..14].* },
        .sender_ip = .{ .value = readU32(payload, 14) },
        .target_mac = .{ .bytes = payload[18..24].* },
        .target_ip = .{ .value = readU32(payload, 24) },
    };
}

pub fn write(
    buf: []u8,
    operation: Operation,
    sender_mac: types.Mac,
    sender_ip: types.Ipv4,
    target_mac: types.Mac,
    target_ip: types.Ipv4,
) Error!usize {
    if (buf.len < 28) return error.NoSpace;

    writeU16(buf, 0, 1);
    writeU16(buf, 2, 0x0800);
    buf[4] = 6;
    buf[5] = 4;
    writeU16(buf, 6, @intFromEnum(operation));
    @memcpy(buf[8..14], &sender_mac.bytes);
    writeU32(buf, 14, sender_ip.value);
    @memcpy(buf[18..24], &target_mac.bytes);
    writeU32(buf, 24, target_ip.value);
    return 28;
}

pub const State = enum {
    incomplete,
    reachable,
    stale,
};

pub const Entry = struct {
    mac: types.Mac,
    port: types.PortId,
    updated_ms: i64,
    state: State = .reachable,
};

pub const Cache = struct {
    map: std.AutoHashMapUnmanaged(u32, Entry) = .empty,

    pub fn deinit(self: *Cache, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
    }

    pub fn reserve(self: *Cache, gpa: std.mem.Allocator, capacity: u32) !void {
        try self.map.ensureTotalCapacity(gpa, capacity);
    }

    pub fn get(self: *const Cache, ip: types.Ipv4) ?Entry {
        return self.map.get(ip.value);
    }

    pub fn getFresh(
        self: *const Cache,
        ip: types.Ipv4,
        port: types.PortId,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        const entry = self.map.get(ip.value) orelse return null;
        if (!entry.port.eql(port)) return null;
        if (now_ms - entry.updated_ms > ttl_ms) return null;
        return entry;
    }

    pub fn put(self: *Cache, gpa: std.mem.Allocator, ip: types.Ipv4, entry: Entry) !void {
        try self.map.put(gpa, ip.value, entry);
    }

    pub fn remove(self: *Cache, ip: types.Ipv4) bool {
        return self.map.remove(ip.value);
    }

    pub fn count(self: *const Cache) usize {
        return self.map.count();
    }
};

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

const mac_a: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0a } };
const mac_b: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0b } };
const zero_mac: types.Mac = .{};

fn testIp(comptime s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

test "arp request round trip" {
    var buf: [28]u8 = undefined;
    const n = try write(&buf, .request, mac_a, testIp("10.0.1.2"), zero_mac, testIp("10.0.1.1"));
    try testing.expectEqual(@as(usize, 28), n);

    const p = try parse(&buf);
    try testing.expectEqual(Operation.request, p.operation);
    try testing.expect(p.sender_mac.eql(mac_a));
    try testing.expect(p.sender_ip.eql(testIp("10.0.1.2")));
    try testing.expect(p.target_mac.isZero());
    try testing.expect(p.target_ip.eql(testIp("10.0.1.1")));
}

test "arp reply round trip" {
    var buf: [28]u8 = undefined;
    _ = try write(&buf, .reply, mac_b, testIp("10.0.1.1"), mac_a, testIp("10.0.1.2"));

    const p = try parse(&buf);
    try testing.expectEqual(Operation.reply, p.operation);
    try testing.expect(p.sender_mac.eql(mac_b));
    try testing.expect(p.target_mac.eql(mac_a));
}

test "arp rejects malformed packets" {
    var buf: [28]u8 = undefined;
    _ = try write(&buf, .request, mac_a, testIp("10.0.1.2"), zero_mac, testIp("10.0.1.1"));

    try testing.expectError(error.Truncated, parse(buf[0..27]));

    var bad = buf;
    bad[4] = 8;
    try testing.expectError(error.Unsupported, parse(&bad));

    bad = buf;
    writeU16(&bad, 6, 3);
    try testing.expectError(error.Unsupported, parse(&bad));
}

test "arp cache freshness and port scoping" {
    var cache: Cache = .{};
    defer cache.deinit(testing.allocator);
    try cache.reserve(testing.allocator, 4);

    const port_a: types.PortId = .{ .value = 1 };
    const port_b: types.PortId = .{ .value = 2 };
    try cache.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = mac_a,
        .port = port_a,
        .updated_ms = 1000,
    });

    try testing.expect(cache.getFresh(testIp("10.0.1.2"), port_a, 1200, 300) != null);
    try testing.expect(cache.getFresh(testIp("10.0.1.2"), port_b, 1200, 300) == null);
    try testing.expect(cache.getFresh(testIp("10.0.1.2"), port_a, 1400, 300) == null);
    try testing.expect(cache.get(testIp("10.0.1.2")).?.mac.eql(mac_a));

    try testing.expect(cache.remove(testIp("10.0.1.2")));
    try testing.expectEqual(@as(usize, 0), cache.count());
}
