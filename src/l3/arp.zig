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
    /// Upper bound on neighbours learned from untrusted L2 traffic. Keeping
    /// this finite is what stops a spoofed-source ARP flood from exhausting
    /// memory.
    pub const max_entries: usize = 1024;

    /// Keyed by `(vlan, ip)`: overlapping subnets on different VLANs must not
    /// share neighbours, even when they arrive on the same trunk port.
    map: std.AutoHashMapUnmanaged(u64, Entry) = .empty,

    pub fn deinit(self: *Cache, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
    }

    pub fn reserve(self: *Cache, gpa: std.mem.Allocator, capacity: u32) !void {
        const limit: u32 = @intCast(max_entries);
        try self.map.ensureTotalCapacity(gpa, @min(capacity, limit));
    }

    pub fn get(self: *const Cache, ip: types.Ipv4) ?Entry {
        return self.getVlan(ip, 0);
    }

    pub fn getVlan(self: *const Cache, ip: types.Ipv4, vlan: u16) ?Entry {
        return self.map.get(cacheKey(ip, vlan));
    }

    pub fn getFresh(
        self: *const Cache,
        ip: types.Ipv4,
        port: types.PortId,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        return self.getFreshVlan(ip, 0, port, now_ms, ttl_ms);
    }

    pub fn getFreshVlan(
        self: *const Cache,
        ip: types.Ipv4,
        vlan: u16,
        port: types.PortId,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        const entry = self.map.get(cacheKey(ip, vlan)) orelse return null;
        if (!entry.port.eql(port)) return null;
        if (now_ms - entry.updated_ms > ttl_ms) return null;
        return entry;
    }

    pub fn getFreshAny(self: *const Cache, ip: types.Ipv4, now_ms: i64, ttl_ms: i64) ?Entry {
        return self.getFreshAnyVlan(ip, 0, now_ms, ttl_ms);
    }

    pub fn getFreshAnyVlan(
        self: *const Cache,
        ip: types.Ipv4,
        vlan: u16,
        now_ms: i64,
        ttl_ms: i64,
    ) ?Entry {
        const entry = self.map.get(cacheKey(ip, vlan)) orelse return null;
        if (now_ms - entry.updated_ms > ttl_ms) return null;
        return entry;
    }

    pub fn put(self: *Cache, gpa: std.mem.Allocator, ip: types.Ipv4, entry: Entry) !void {
        return self.putVlan(gpa, ip, 0, entry);
    }

    pub fn putVlan(
        self: *Cache,
        gpa: std.mem.Allocator,
        ip: types.Ipv4,
        vlan: u16,
        entry: Entry,
    ) !void {
        const key = cacheKey(ip, vlan);
        if (self.map.getPtr(key)) |slot| {
            slot.* = entry;
            return;
        }
        if (self.map.count() >= max_entries and !self.evictOldest()) {
            return error.NoSpace;
        }
        try self.map.put(gpa, key, entry);
    }

    /// Drops entries that have not been refreshed within `ttl_ms`. Called from
    /// the periodic tick so stale neighbours do not occupy the bounded cache.
    pub fn prune(self: *Cache, now_ms: i64, ttl_ms: i64) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const age = now_ms - entry.value_ptr.updated_ms;
            if (age > ttl_ms) self.map.removeByPtr(entry.key_ptr);
        }
    }

    pub fn remove(self: *Cache, ip: types.Ipv4) bool {
        return self.removeVlan(ip, 0);
    }

    pub fn removeVlan(self: *Cache, ip: types.Ipv4, vlan: u16) bool {
        return self.map.remove(cacheKey(ip, vlan));
    }

    pub fn count(self: *const Cache) usize {
        return self.map.count();
    }

    fn evictOldest(self: *Cache) bool {
        var oldest_key: ?u64 = null;
        var oldest_ms: i64 = std.math.maxInt(i64);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.updated_ms < oldest_ms) {
                oldest_ms = entry.value_ptr.updated_ms;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |key| return self.map.remove(key);
        return false;
    }
};

fn cacheKey(ip: types.Ipv4, vlan: u16) u64 {
    return (@as(u64, vlan) << 32) | ip.value;
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

test "arp cache stays bounded and evicts the oldest entry" {
    var cache: Cache = .{};
    defer cache.deinit(testing.allocator);

    const port: types.PortId = .{ .value = 1 };
    var i: u32 = 0;
    while (i <= Cache.max_entries) : (i += 1) {
        try cache.put(testing.allocator, .{ .value = 0x0a000001 + i }, .{
            .mac = mac_a,
            .port = port,
            .updated_ms = i,
        });
    }

    try testing.expectEqual(Cache.max_entries, cache.count());
    try testing.expect(cache.get(.{ .value = 0x0a000001 }) == null);
    try testing.expect(cache.get(.{ .value = 0x0a000001 + @as(u32, @intCast(Cache.max_entries)) }) != null);
}

test "arp cache prune drops stale entries" {
    var cache: Cache = .{};
    defer cache.deinit(testing.allocator);

    const port: types.PortId = .{ .value = 1 };
    try cache.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = mac_a,
        .port = port,
        .updated_ms = 1000,
    });
    try cache.put(testing.allocator, testIp("10.0.1.3"), .{
        .mac = mac_b,
        .port = port,
        .updated_ms = 2000,
    });

    cache.prune(2500, 1000);
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expect(cache.get(testIp("10.0.1.2")) == null);
    try testing.expect(cache.get(testIp("10.0.1.3")) != null);
}

test "arp cache separates overlapping subnets by vlan" {
    var cache: Cache = .{};
    defer cache.deinit(testing.allocator);

    const port: types.PortId = .{ .value = 1 };
    try cache.putVlan(testing.allocator, testIp("10.0.1.2"), 10, .{
        .mac = mac_a,
        .port = port,
        .updated_ms = 1000,
    });
    try cache.putVlan(testing.allocator, testIp("10.0.1.2"), 20, .{
        .mac = mac_b,
        .port = port,
        .updated_ms = 1000,
    });

    try testing.expect(cache.getVlan(testIp("10.0.1.2"), 10).?.mac.eql(mac_a));
    try testing.expect(cache.getVlan(testIp("10.0.1.2"), 20).?.mac.eql(mac_b));
    try testing.expect(cache.getVlan(testIp("10.0.1.2"), 30) == null);
    try testing.expect(cache.getVlan(testIp("10.0.1.2"), 0) == null);
    try testing.expectEqual(@as(usize, 2), cache.count());
}
