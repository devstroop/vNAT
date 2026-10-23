//! Linux kernel-bridge offload planning and setup.
//!
//! An offloaded bridge is owned by the kernel bridge driver. vNAT keeps
//! routing, DHCP, NAT and firewall in userspace by attaching one veth trunk
//! per bridge: the bridge-side end is enslaved (and configured as a VLAN
//! trunk), while vNAT opens the peer as its only synthetic L2 port.
//!
//! All host mutations go through `Host`, so a failed apply can be rolled back
//! to the exact journal checkpoint it started from and `vnat down` restores
//! the pre-start state.

const std = @import("std");
const schema = @import("../config/schema.zig");
const Host = @import("host.zig").Host;
const netlink = @import("../port/linux/netlink.zig");
const iface = @import("../port/linux/iface.zig");

pub const SyntheticPort = struct {
    config_name: []const u8,
    device: []const u8,
};

pub const Device = struct {
    bridge_name: []const u8,
    kernel_bridge: []const u8,
    veth_vnat: []const u8,
    veth_bridge: []const u8,
    vlan_aware: bool,
    stp: bool,
};

pub const Plan = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    devices: []const Device = &.{},
    synthetic: []const SyntheticPort = &.{},
    skipped: []const []const u8 = &.{},

    pub fn init(gpa: std.mem.Allocator) Plan {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn isEnabled(cfg: *const schema.Config) bool {
    var it = cfg.bridges.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.offload == .kernel) return true;
    }
    return false;
}

pub fn apply(
    io: std.Io,
    gpa: std.mem.Allocator,
    host: *Host,
    cfg: *const schema.Config,
) !Plan {
    var plan = Plan.init(gpa);
    errdefer plan.deinit();
    if (!isEnabled(cfg)) return plan;

    const a = plan.arena.allocator();
    var devices: std.ArrayListUnmanaged(Device) = .empty;
    var synthetic: std.ArrayListUnmanaged(SyntheticPort) = .empty;
    var skipped: std.ArrayListUnmanaged([]const u8) = .empty;

    var it = cfg.bridges.iterator();
    while (it.next()) |entry| {
        const bridge_name = entry.key_ptr.*;
        const bridge = entry.value_ptr.*;
        if (bridge.offload != .kernel) continue;

        const names = try deviceNames(a, cfg.instance, bridge_name);
        for (devices.items) |existing| {
            if (std.mem.eql(u8, existing.kernel_bridge, names.bridge)) {
                return error.AddressInUse;
            }
        }
        try preflight(io, a, cfg, bridge, names);

        try devices.append(a, .{
            .bridge_name = bridge_name,
            .kernel_bridge = names.bridge,
            .veth_vnat = names.vnat,
            .veth_bridge = names.bridge_side,
            .vlan_aware = bridge.vlan_aware,
            .stp = bridge.stp,
        });
        try synthetic.append(a, .{
            .config_name = bridge_name,
            .device = names.vnat,
        });
        for (bridge.ports) |port_name| {
            try skipped.append(a, port_name);
        }
    }

    plan.devices = try devices.toOwnedSlice(a);
    plan.synthetic = try synthetic.toOwnedSlice(a);
    plan.skipped = try skipped.toOwnedSlice(a);

    const checkpoint = try host.checkpoint();
    errdefer {
        _ = host.downTo(checkpoint) catch {};
    }

    for (plan.devices) |device| {
        const bridge = cfg.bridges.getPtr(device.bridge_name) orelse return error.NotFound;

        _ = try host.ifaceAddBridge(device.kernel_bridge, bridge.stp, bridge.vlan_aware);
        _ = try host.ifaceAddVeth(device.veth_vnat, device.veth_bridge);
        _ = try host.ifaceSetMaster(device.veth_bridge, device.kernel_bridge);

        for (bridge.ports) |port_name| {
            const port = cfg.ports.get(port_name) orelse return error.NotFound;
            _ = try host.ifaceSetMaster(port.device, device.kernel_bridge);
            if (bridge.vlan_aware) {
                const pvid = port.pvid orelse 1;
                _ = try host.bridgeVlanAdd(port.device, pvid, true, true);
                for (port.tagged) |vid| {
                    if (vid == pvid) continue;
                    _ = try host.bridgeVlanAdd(port.device, vid, false, false);
                }
            }
        }

        if (bridge.vlan_aware) {
            _ = try host.bridgeVlanAdd(device.veth_bridge, 1, true, true);
            for (try trunkVlans(a, cfg, device.bridge_name, bridge.*)) |vid| {
                if (vid == 1) continue;
                _ = try host.bridgeVlanAdd(device.veth_bridge, vid, false, false);
            }
        }

        _ = try host.ifaceSetUp(device.kernel_bridge, true);
        _ = try host.ifaceSetUp(device.veth_vnat, true);
        _ = try host.ifaceSetUp(device.veth_bridge, true);
        for (bridge.ports) |port_name| {
            const port = cfg.ports.get(port_name) orelse return error.NotFound;
            _ = try host.ifaceSetUp(port.device, true);
        }
    }

    return plan;
}

const DeviceNames = struct {
    bridge: []const u8,
    vnat: []const u8,
    bridge_side: []const u8,
};

fn deviceNames(a: std.mem.Allocator, instance: []const u8, bridge_name: []const u8) !DeviceNames {
    const suffix = nameHash(instance, bridge_name);
    return .{
        .bridge = try std.fmt.allocPrint(a, "vnatbr{x}", .{suffix}),
        .vnat = try std.fmt.allocPrint(a, "vnatp{x}", .{suffix}),
        .bridge_side = try std.fmt.allocPrint(a, "vnatb{x}", .{suffix}),
    };
}

fn nameHash(instance: []const u8, bridge_name: []const u8) u32 {
    var hash: u32 = 2_166_136_261;
    for (instance) |c| {
        hash ^= c;
        hash *%= 16_777_619;
    }
    hash ^= 0xff;
    hash *%= 16_777_619;
    for (bridge_name) |c| {
        hash ^= c;
        hash *%= 16_777_619;
    }
    return hash;
}

fn preflight(
    io: std.Io,
    a: std.mem.Allocator,
    cfg: *const schema.Config,
    bridge: schema.BridgeConfig,
    names: DeviceNames,
) !void {
    try ensureAbsent(names.bridge);
    try ensureAbsent(names.vnat);
    try ensureAbsent(names.bridge_side);

    for (bridge.ports) |port_name| {
        const port = cfg.ports.get(port_name) orelse return error.NotFound;
        if (port.create != null) return error.InvalidArgument;
        _ = try iface.ifindex(port.device);
        if (try netlink.linkMaster(io, a, port.device) != 0) return error.Busy;
    }

    // Catch a port listed twice in one bridge even if validation was bypassed.
    for (bridge.ports, 0..) |port_name, i| {
        for (bridge.ports[0..i]) |seen| {
            if (std.mem.eql(u8, seen, port_name)) return error.InvalidArgument;
        }
    }

    if (bridge.vlan_aware) {
        for (bridge.ports) |port_name| {
            const port = cfg.ports.get(port_name) orelse return error.NotFound;
            const pvid = port.pvid orelse 1;
            for (port.tagged) |vid| {
                // A kernel bridge VLAN entry is either PVID-untagged or
                // tagged, never both. Reject rather than silently changing
                // userspace bridge semantics.
                if (vid == pvid) return error.InvalidArgument;
            }
        }
    }
}

fn ensureAbsent(name: []const u8) !void {
    _ = iface.ifindex(name) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.Busy;
}

fn trunkVlans(
    a: std.mem.Allocator,
    cfg: *const schema.Config,
    bridge_name: []const u8,
    bridge: schema.BridgeConfig,
) ![]const u16 {
    var seen = [_]bool{false} ** 4096;
    seen[1] = true;

    for (bridge.ports) |port_name| {
        const port = cfg.ports.get(port_name) orelse return error.NotFound;
        const pvid = port.pvid orelse 1;
        if (pvid >= seen.len) return error.InvalidArgument;
        seen[pvid] = true;
        for (port.tagged) |vid| {
            if (vid >= seen.len) return error.InvalidArgument;
            seen[vid] = true;
        }
    }

    var iface_it = cfg.interfaces.iterator();
    while (iface_it.next()) |entry| {
        const itf = entry.value_ptr.*;
        if (itf.bridge) |name| {
            if (!std.mem.eql(u8, name, bridge_name)) continue;
            const vlan = itf.vlan orelse 1;
            if (vlan >= seen.len) return error.InvalidArgument;
            seen[vlan] = true;
        }
    }

    var out: std.ArrayListUnmanaged(u16) = .empty;
    for (seen, 0..) |present, vid| {
        if (present and vid != 0) try out.append(a, @intCast(vid));
    }
    return out.toOwnedSlice(a);
}

const testing = std.testing;

test "offload device names fit IFNAMSIZ and are stable" {
    const a = testing.allocator;
    const one = try deviceNames(a, "instance", "lan-bridge");
    defer {
        a.free(one.bridge);
        a.free(one.vnat);
        a.free(one.bridge_side);
    }
    const two = try deviceNames(a, "instance", "lan-bridge");
    defer {
        a.free(two.bridge);
        a.free(two.vnat);
        a.free(two.bridge_side);
    }
    try testing.expect(one.bridge.len < 16);
    try testing.expect(one.vnat.len < 16);
    try testing.expect(one.bridge_side.len < 16);
    try testing.expectEqualStrings(one.bridge, two.bridge);
    try testing.expectEqualStrings(one.vnat, two.vnat);
    try testing.expectEqualStrings(one.bridge_side, two.bridge_side);
}

test "trunk VLANs union members and SVIs" {
    var parsed = try @import("../config/parse.zig").parse(testing.allocator,
        \\{ "version": 1, "instance": "x",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "eth1", "pvid": 10, "tagged": [20, 30] },
        \\    "b": { "kind": "l2", "device": "eth2", "pvid": 40 }
        \\  },
        \\  "bridges": { "br": { "ports": ["a", "b"], "vlan_aware": true, "offload": "kernel" } },
        \\  "interfaces": {
        \\    "lan0": { "bridge": "br", "address": "10.0.10.1/24", "vlan": 10 },
        \\    "guest0": { "bridge": "br", "address": "10.0.50.1/24", "vlan": 50 }
        \\  } }
    );
    defer parsed.deinit();

    const bridge = parsed.config.bridges.get("br").?;
    const vlans = try trunkVlans(testing.allocator, &parsed.config, "br", bridge);
    defer testing.allocator.free(vlans);

    try testing.expectEqualSlices(u16, &.{ 1, 10, 20, 30, 40, 50 }, vlans);
}

test "trunk VLANs rejects out-of-range VLAN IDs" {
    var parsed = try @import("../config/parse.zig").parse(testing.allocator,
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1", "pvid": 5000 } },
        \\  "bridges": { "br": { "ports": ["lan"], "vlan_aware": true, "offload": "kernel" } } }
    );
    defer parsed.deinit();

    const bridge = parsed.config.bridges.get("br").?;
    try testing.expectError(
        error.InvalidArgument,
        trunkVlans(testing.allocator, &parsed.config, "br", bridge),
    );
}

test "offload is disabled without kernel bridges" {
    var parsed = try @import("../config/parse.zig").parse(testing.allocator,
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["lan"] } } }
    );
    defer parsed.deinit();
    try testing.expect(!isEnabled(&parsed.config));
}

test "kernel offload is detected" {
    var parsed = try @import("../config/parse.zig").parse(testing.allocator,
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["lan"], "offload": "kernel" } } }
    );
    defer parsed.deinit();
    try testing.expect(isEnabled(&parsed.config));
}
