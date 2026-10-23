//! IPv4 forwarding table with longest-prefix match. R2 keeps a small flat
//! table; R3 replaces the lookup with a compressed trie once route counts grow.

const std = @import("std");
const types = @import("../types.zig");

pub const Kind = enum {
    connected,
    static,
};

pub const Route = struct {
    prefix: types.Prefix4,
    next_hop: ?types.Ipv4 = null,
    port: types.PortId,
    metric: u32 = 0,
    kind: Kind = .static,
};

pub const Fib = struct {
    routes: std.ArrayListUnmanaged(Route) = .empty,

    pub fn deinit(self: *Fib, gpa: std.mem.Allocator) void {
        self.routes.deinit(gpa);
    }

    pub fn add(self: *Fib, gpa: std.mem.Allocator, route: Route) !void {
        for (self.routes.items) |*existing| {
            if (existing.prefix.eql(route.prefix) and existing.port.eql(route.port)) {
                existing.* = route;
                return;
            }
        }
        try self.routes.append(gpa, route);
    }

    pub fn remove(self: *Fib, prefix: types.Prefix4, port: types.PortId) bool {
        for (self.routes.items, 0..) |route, i| {
            if (route.prefix.eql(prefix) and route.port.eql(port)) {
                _ = self.routes.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn lookup(self: *const Fib, dst: types.Ipv4) ?Route {
        var best: ?Route = null;
        for (self.routes.items) |route| {
            if (!route.prefix.contains(dst)) continue;
            if (best == null) {
                best = route;
                continue;
            }
            const current = best.?;
            if (route.prefix.len > current.prefix.len) {
                best = route;
            } else if (route.prefix.len == current.prefix.len and route.metric < current.metric) {
                best = route;
            }
        }
        return best;
    }

    pub fn count(self: *const Fib) usize {
        return self.routes.items.len;
    }
};

const testing = std.testing;

fn testPrefix(comptime s: []const u8) types.Prefix4 {
    return types.Prefix4.parse(s) catch unreachable;
}

fn testIp(comptime s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

const port_a: types.PortId = .{ .value = 1 };
const port_b: types.PortId = .{ .value = 2 };

test "fib longest prefix match" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.1.0/24"), .port = port_a, .kind = .connected });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.2.0/24"), .port = port_b, .kind = .connected });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("0.0.0.0/0"), .next_hop = testIp("10.0.1.1"), .port = port_a });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.2.128/25"), .port = port_b, .kind = .connected });

    try testing.expectEqual(@as(u8, 25), fib.lookup(testIp("10.0.2.200")).?.prefix.len);
    try testing.expectEqual(@as(u8, 24), fib.lookup(testIp("10.0.2.5")).?.prefix.len);
    try testing.expectEqual(@as(u8, 0), fib.lookup(testIp("8.8.8.8")).?.prefix.len);
    try testing.expect(fib.lookup(testIp("8.8.8.8")).?.next_hop.?.eql(testIp("10.0.1.1")));
    try testing.expect(fib.lookup(testIp("192.168.1.1")) != null);
}

test "fib metric breaks equal prefixes" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.9.0.0/16"), .port = port_a, .metric = 100 });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.9.0.0/16"), .port = port_b, .metric = 10 });

    try testing.expect(fib.lookup(testIp("10.9.1.1")).?.port.eql(port_b));
}

test "fib replace, remove and miss" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.0.0/8"), .port = port_a, .metric = 50 });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.0.0/8"), .port = port_a, .metric = 5 });
    try testing.expectEqual(@as(usize, 1), fib.count());
    try testing.expectEqual(@as(u32, 5), fib.lookup(testIp("10.1.2.3")).?.metric);

    try testing.expect(fib.remove(testPrefix("10.0.0.0/8"), port_a));
    try testing.expect(fib.lookup(testIp("10.1.2.3")) == null);
    try testing.expect(!fib.remove(testPrefix("10.0.0.0/8"), port_a));
}

test "fib normalizes prefix equality" {
    var fib: Fib = .{};
    defer fib.deinit(testing.allocator);

    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.5.0/24"), .port = port_a });
    try fib.add(testing.allocator, .{ .prefix = testPrefix("10.0.5.99/24"), .port = port_a });
    try testing.expectEqual(@as(usize, 1), fib.count());
    try testing.expect(fib.lookup(testIp("10.0.5.1")).?.prefix.eql(testPrefix("10.0.5.0/24")));
}
