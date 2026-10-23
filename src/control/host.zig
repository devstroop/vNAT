//! Linux host mutations with journal-before-apply semantics. Ownership is
//! derived from the journal: `iface del` and `route del` only touch state that
//! vNAT added, and `down` replays the inverse of every recorded operation.

const std = @import("std");
const types = @import("../types.zig");
const journal = @import("journal.zig");
const netlink = @import("../port/linux/netlink.zig");
const iface_mod = @import("../port/linux/iface.zig");
const PortError = @import("../errors.zig").PortError;

pub const Change = enum {
    applied,
    noop,
};

pub const DownResult = struct {
    restored: usize = 0,
    failed: usize = 0,
};

pub const Host = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    store: journal.Store,

    pub fn init(
        io: std.Io,
        gpa: std.mem.Allocator,
        state_dir: []const u8,
        instance: []const u8,
    ) !Host {
        var store = try journal.Store.open(io, gpa, state_dir, instance);
        errdefer store.deinit(io);
        return .{ .io = io, .gpa = gpa, .store = store };
    }

    pub fn deinit(self: *Host) void {
        self.store.deinit(self.io);
    }

    pub fn journalContents(self: *Host) !?[]u8 {
        return self.store.contents(self.io);
    }

    pub fn ifaceSet(self: *Host, dev: []const u8, cidr: []const u8) !Change {
        const prefix = types.Prefix4.parse(cidr) catch return error.InvalidArgument;
        _ = try iface_mod.ifindex(dev);

        const contents = try self.readContents();
        defer self.gpa.free(contents);
        if (try journal.ownsAddress(self.gpa, contents, dev, prefix)) return .noop;

        try self.store.append(self.io, .{ .addr_add = .{ .dev = dev, .prefix = prefix } });
        netlink.addAddress(self.io, dev, prefix) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn ifaceDel(self: *Host, dev: []const u8, cidr: []const u8) !Change {
        const prefix = types.Prefix4.parse(cidr) catch return error.InvalidArgument;
        _ = try iface_mod.ifindex(dev);

        const contents = try self.readContents();
        defer self.gpa.free(contents);
        if (!try journal.ownsAddress(self.gpa, contents, dev, prefix)) return error.NotManaged;

        try self.store.append(self.io, .{ .addr_del = .{ .dev = dev, .prefix = prefix } });
        netlink.deleteAddress(self.io, dev, prefix) catch |err| {
            self.store.removeLast(self.io) catch {};
            return if (err == error.NotFound) .noop else err;
        };
        return .applied;
    }

    pub fn ifaceSetUp(self: *Host, dev: []const u8, up: bool) !Change {
        const current = try iface_mod.isUp(dev);
        if (current == up) return .noop;

        try self.store.append(self.io, .{ .link = .{ .dev = dev, .up = up } });
        iface_mod.setUp(dev, up) catch |err| {
            self.store.removeLast(self.io) catch {};
            return err;
        };
        return .applied;
    }

    pub fn ifaceAddBridge(self: *Host, dev: []const u8, stp: bool, vlan_filtering: bool) !Change {
        if (try linkExists(dev)) return error.Busy;
        try self.store.append(self.io, .{ .link_add = .{
            .dev = dev,
            .kind = .bridge,
            .stp = stp,
            .vlan_filtering = vlan_filtering,
        } });
        netlink.createLink(self.io, .{
            .name = dev,
            .kind = .bridge,
            .stp = stp,
            .vlan_filtering = vlan_filtering,
        }) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn ifaceAddVeth(self: *Host, dev: []const u8, peer: []const u8) !Change {
        if (try linkExists(dev) or try linkExists(peer)) return error.Busy;
        try self.store.append(self.io, .{ .link_add = .{
            .dev = dev,
            .kind = .veth,
            .peer = peer,
        } });
        netlink.createLink(self.io, .{
            .name = dev,
            .kind = .veth,
            .peer = peer,
        }) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn ifaceSetMaster(self: *Host, dev: []const u8, master: ?[]const u8) !Change {
        const current = try netlink.linkMaster(self.io, self.gpa, dev);
        const target: u32 = if (master) |name| try iface_mod.ifindex(name) else 0;
        if (current == target) return .noop;

        try self.store.append(self.io, .{ .link_master = .{
            .dev = dev,
            .master = master,
        } });
        netlink.setMaster(self.io, dev, master) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn bridgeVlanAdd(
        self: *Host,
        dev: []const u8,
        vid: u16,
        pvid: bool,
        untagged: bool,
    ) !Change {
        if (pvid and !untagged) return error.InvalidArgument;
        try self.store.append(self.io, .{ .bridge_vlan = .{
            .dev = dev,
            .vid = vid,
            .pvid = pvid,
            .untagged = untagged,
        } });
        netlink.setBridgeVlan(self.io, dev, vid, pvid, untagged, true) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn checkpoint(self: *Host) !usize {
        return self.store.lineCount(self.io);
    }

    pub fn routeAdd(
        self: *Host,
        dst: []const u8,
        via: ?[]const u8,
        dev: []const u8,
        metric: u32,
        table: u32,
    ) !Change {
        const route = try parseRoute(dst, via, dev, metric, table);
        const ifindex = try iface_mod.ifindex(dev);

        const contents = try self.readContents();
        defer self.gpa.free(contents);
        if (try journal.ownsRoute(self.gpa, contents, route)) return .noop;

        try self.store.append(self.io, .{ .route_add = route });
        netlink.addRoute(self.io, .{
            .prefix = route.prefix,
            .via = route.via,
            .ifindex = ifindex,
            .metric = route.metric,
            .table = route.table,
        }) catch |err| {
            try self.store.removeLast(self.io);
            return err;
        };
        return .applied;
    }

    pub fn routeDel(
        self: *Host,
        dst: []const u8,
        via: ?[]const u8,
        dev: []const u8,
        metric: u32,
        table: u32,
    ) !Change {
        const route = try parseRoute(dst, via, dev, metric, table);
        const ifindex = try iface_mod.ifindex(dev);

        const contents = try self.readContents();
        defer self.gpa.free(contents);
        if (!try journal.ownsRoute(self.gpa, contents, route)) return error.NotManaged;

        try self.store.append(self.io, .{ .route_del = route });
        netlink.deleteRoute(self.io, .{
            .prefix = route.prefix,
            .via = route.via,
            .ifindex = ifindex,
            .metric = route.metric,
            .table = route.table,
        }) catch |err| {
            self.store.removeLast(self.io) catch {};
            return if (err == error.NotFound) .noop else err;
        };
        return .applied;
    }

    pub fn down(self: *Host) !DownResult {
        return self.downTo(0);
    }

    /// Replays only records written after `checkpoint`, newest first, then
    /// truncates them. Lets setup code roll back a failed transaction without
    /// disturbing earlier user-visible host state.
    pub fn downTo(self: *Host, start: usize) !DownResult {
        const contents_opt = try self.store.contents(self.io);
        const contents = contents_opt orelse return .{};
        defer self.gpa.free(contents);

        var lines: std.ArrayListUnmanaged([]const u8) = .empty;
        defer lines.deinit(self.gpa);

        var it = std.mem.splitScalar(u8, contents, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            try lines.append(self.gpa, line);
        }
        if (start > lines.items.len) return error.InvalidJournal;

        var result: DownResult = .{};
        var index = lines.items.len;
        while (index > start) {
            index -= 1;
            var parsed = journal.parseLine(self.gpa, lines.items[index]) catch {
                result.failed += 1;
                continue;
            };
            defer parsed.deinit();
            const op = journal.toOp(parsed.value) catch {
                result.failed += 1;
                continue;
            };
            self.applyInverse(op) catch {
                result.failed += 1;
                continue;
            };
            result.restored += 1;
        }

        if (result.failed == 0) try self.store.truncateTo(self.io, start);
        return result;
    }

    fn applyInverse(self: *Host, op: journal.Op) !void {
        switch (op) {
            .addr_add => |address| {
                _ = iface_mod.ifindex(address.dev) catch |err| switch (err) {
                    error.NotFound => return,
                    else => return err,
                };
                netlink.deleteAddress(self.io, address.dev, address.prefix) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            },
            .addr_del => |address| {
                _ = try iface_mod.ifindex(address.dev);
                netlink.addAddress(self.io, address.dev, address.prefix) catch |err| switch (err) {
                    error.Busy => {},
                    else => return err,
                };
            },
            .link => |link| {
                const target = !link.up;
                const current = try iface_mod.isUp(link.dev);
                if (current != target) try iface_mod.setUp(link.dev, target);
            },
            .link_add => |link| {
                _ = iface_mod.ifindex(link.dev) catch |err| switch (err) {
                    error.NotFound => return,
                    else => return err,
                };
                netlink.deleteLink(self.io, link.dev) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            },
            .link_master => |link| {
                _ = iface_mod.ifindex(link.dev) catch |err| switch (err) {
                    error.NotFound => return,
                    else => return err,
                };
                netlink.setMaster(self.io, link.dev, null) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            },
            .bridge_vlan => |vlan| {
                _ = iface_mod.ifindex(vlan.dev) catch |err| switch (err) {
                    error.NotFound => return,
                    else => return err,
                };
                netlink.setBridgeVlan(self.io, vlan.dev, vlan.vid, vlan.pvid, vlan.untagged, false) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            },
            .route_add => |route| {
                const ifindex = iface_mod.ifindex(route.dev) catch |err| switch (err) {
                    error.NotFound => return,
                    else => return err,
                };
                netlink.deleteRoute(self.io, routeSpec(route, ifindex)) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            },
            .route_del => |route| {
                const ifindex = try iface_mod.ifindex(route.dev);
                netlink.addRoute(self.io, routeSpec(route, ifindex)) catch |err| switch (err) {
                    error.Busy => {},
                    else => return err,
                };
            },
        }
    }

    fn readContents(self: *Host) ![]u8 {
        const contents_opt = try self.store.contents(self.io);
        return contents_opt orelse try self.gpa.alloc(u8, 0);
    }
};

fn linkExists(dev: []const u8) !bool {
    _ = iface_mod.ifindex(dev) catch |err| switch (err) {
        error.NotFound => return false,
        else => return err,
    };
    return true;
}

fn parseRoute(
    dst: []const u8,
    via: ?[]const u8,
    dev: []const u8,
    metric: u32,
    table: u32,
) !journal.Route {
    const prefix = types.Prefix4.parse(dst) catch return error.InvalidArgument;
    const next_hop: ?types.Ipv4 = if (via) |text|
        types.Ipv4.parse(text) catch return error.InvalidArgument
    else
        null;
    if (dev.len == 0) return error.InvalidArgument;
    return .{
        .prefix = prefix,
        .via = next_hop,
        .dev = dev,
        .metric = metric,
        .table = if (table == 254) 0 else table,
    };
}

fn routeSpec(route: journal.Route, ifindex: u32) netlink.RouteSpec {
    return .{
        .prefix = route.prefix,
        .via = route.via,
        .ifindex = ifindex,
        .metric = route.metric,
        .table = route.table,
    };
}

const testing = std.testing;

test "down keeps the journal when a record cannot be parsed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const store = try journal.Store.init(testing.allocator, tmp.dir, "test", false);
    var host = Host{ .io = testing.io, .gpa = testing.allocator, .store = store };
    defer host.deinit();

    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "test.journal",
        .data = "not json\n",
    });

    const result = try host.down();
    try testing.expectEqual(@as(usize, 1), result.failed);
    try testing.expectEqual(@as(usize, 0), result.restored);

    const contents = (try host.journalContents()).?;
    defer testing.allocator.free(contents);
    try testing.expectEqualStrings("not json\n", contents);
}
