//! Semantic validation for a parsed configuration.
//!
//! Parsing checks shape and types; this module checks meaning: references,
//! membership conflicts, address syntax and subnet consistency.

const std = @import("std");
const schema = @import("schema.zig");
const types = @import("../types.zig");
const ConfigError = @import("../errors.zig").ConfigError;

pub fn validate(cfg: *const schema.Config) ConfigError!void {
    if (cfg.version != 1) return error.InvalidVersion;
    try validateInstance(cfg.instance);

    try validatePorts(cfg);
    try validateBridges(cfg);
    try validateInterfaces(cfg);
    try validateRoutes(cfg);
    try validateNat(cfg);
    try validateDhcp(cfg);
    try validateDns(cfg);
    try validateFirewall(cfg);
}

fn validateFirewall(cfg: *const schema.Config) ConfigError!void {
    // Outbound allow rules are not implemented yet; accepting the policy
    // silently would make `default_out: "drop"` a no-op.
    if (cfg.firewall.default_out != .accept) return error.InvalidValue;

    if (cfg.firewall.rules.len > 4096) return error.InvalidValue;
    for (cfg.firewall.rules) |rule| {
        if (rule.src) |src| _ = types.Prefix4.parse(src) catch return error.InvalidValue;
        if (rule.dst) |dst| _ = types.Prefix4.parse(dst) catch return error.InvalidValue;
        if (rule.sport != null or rule.dport != null) {
            if (rule.proto != .tcp and rule.proto != .udp) return error.InvalidValue;
        }
        if (rule.sport) |port| if (port == 0) return error.InvalidValue;
        if (rule.dport) |port| if (port == 0) return error.InvalidValue;
        if (rule.iif) |name| try validateFirewallIface(cfg, name);
        if (rule.oif) |name| try validateFirewallIface(cfg, name);
        for (rule.ct_state, 0..) |state, i| {
            for (rule.ct_state[0..i]) |seen| {
                if (seen == state) return error.InvalidValue;
            }
        }
    }
}

fn validateFirewallIface(cfg: *const schema.Config, name: []const u8) ConfigError!void {
    if (!cfg.ports.contains(name) and
        !cfg.interfaces.contains(name) and
        !cfg.bridges.contains(name))
    {
        return error.UndefinedReference;
    }
}

fn validateInstance(instance: []const u8) ConfigError!void {
    if (instance.len == 0 or instance.len > 64) return error.InvalidValue;
    for (instance) |c| {
        if (c < 0x20 or c == 0x7f) return error.InvalidValue;
        if (c == '/' or c == '\\') return error.InvalidValue;
    }
}

fn validatePorts(cfg: *const schema.Config) ConfigError!void {
    var it = cfg.ports.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > 64) return error.InvalidValue;
        if (cfg.bridges.contains(name) or cfg.interfaces.contains(name)) {
            return error.DuplicateName;
        }

        const port = entry.value_ptr.*;
        if (port.device.len == 0 or port.device.len >= 16) return error.InvalidValue;
        if (port.kind == .l3 and port.create == null) {
            // Existing L3 devices have no fd vNAT can adopt; only TUN can be
            // created and owned by the daemon.
            return error.InvalidValue;
        }
        if (port.create) |create| {
            switch (create) {
                .tun => if (port.kind != .l3) return error.InvalidValue,
                .tap => if (port.kind != .l2) return error.InvalidValue,
            }
        }
        if (port.mtu) |mtu| {
            if (mtu < 576 or mtu > types.max_supported_mtu) return error.InvalidValue;
        }
        if (!portInAnyBridge(cfg, name) and
            (port.pvid != null or port.tagged.len != 0))
        {
            return error.InvalidValue;
        }

        var other = cfg.ports.iterator();
        while (other.next()) |other_entry| {
            if (std.mem.eql(u8, other_entry.key_ptr.*, name)) continue;
            if (std.mem.eql(u8, other_entry.value_ptr.device, port.device)) {
                return error.DuplicateName;
            }
        }
    }
}

fn validateBridges(cfg: *const schema.Config) ConfigError!void {
    var it = cfg.bridges.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > 64) return error.InvalidValue;
        if (cfg.interfaces.contains(name)) return error.DuplicateName;

        const bridge = entry.value_ptr.*;
        if (bridge.ports.len == 0) return error.InvalidValue;
        if (bridge.stp) return error.InvalidValue;
        if (bridge.offload != .none) return error.InvalidValue;

        for (bridge.ports, 0..) |port_name, i| {
            const port = cfg.ports.getPtr(port_name) orelse return error.UndefinedReference;
            if (port.kind != .l2) return error.InvalidValue;
            try validatePortVlans(port, bridge.vlan_aware);

            for (bridge.ports[0..i]) |seen| {
                if (std.mem.eql(u8, seen, port_name)) return error.DuplicateName;
            }
        }
    }

    // A port belongs to at most one bridge.
    var a = cfg.bridges.iterator();
    while (a.next()) |ea| {
        for (ea.value_ptr.ports) |port_name| {
            var b = cfg.bridges.iterator();
            while (b.next()) |eb| {
                if (ea.value_ptr == eb.value_ptr) continue;
                for (eb.value_ptr.ports) |other| {
                    if (std.mem.eql(u8, other, port_name)) return error.InvalidValue;
                }
            }
        }
    }
}

fn validateInterfaces(cfg: *const schema.Config) ConfigError!void {
    var it = cfg.interfaces.iterator();
    while (it.next()) |entry| {
        const itf = entry.value_ptr.*;
        const has_bridge = itf.bridge != null;
        const has_port = itf.port != null;

        if (has_bridge == has_port) return error.InvalidValue;
        if (itf.vlan) |vlan| {
            if (vlan == 0 or vlan > 4094) return error.InvalidValue;
        }

        if (itf.bridge) |bridge_name| {
            const bridge = cfg.bridges.getPtr(bridge_name) orelse return error.UndefinedReference;
            if (itf.vlan != null and !bridge.vlan_aware) return error.InvalidValue;
            if (itf.address) |address| {
                if (std.mem.eql(u8, address, "dhcp")) return error.InvalidValue;
            }
        }
        if (itf.port) |port| {
            if (!cfg.ports.contains(port)) return error.UndefinedReference;
            if (portInAnyBridge(cfg, port)) return error.InvalidValue;
            if (itf.vlan != null) return error.InvalidValue;
        }
        if (itf.address) |address| {
            if (!std.mem.eql(u8, address, "dhcp")) {
                _ = types.Prefix4.parse(address) catch return error.InvalidValue;
            }
        }
    }
}

fn validateRoutes(cfg: *const schema.Config) ConfigError!void {
    for (cfg.routes) |route| {
        _ = types.Prefix4.parse(route.dst) catch return error.InvalidValue;
        if (route.via) |via| {
            _ = types.Ipv4.parse(via) catch return error.InvalidValue;
        }
        const dev = route.dev orelse return error.InvalidValue;
        if (!cfg.ports.contains(dev) and !cfg.interfaces.contains(dev)) {
            return error.UndefinedReference;
        }
        if (cfg.ports.contains(dev) and portInAnyBridge(cfg, dev)) {
            return error.InvalidValue;
        }
    }
}

fn validateNat(cfg: *const schema.Config) ConfigError!void {
    for (cfg.nat.masquerade) |m| {
        if (!cfg.interfaces.contains(m.out) and !cfg.ports.contains(m.out)) {
            return error.UndefinedReference;
        }
        if (cfg.ports.contains(m.out) and portInAnyBridge(cfg, m.out)) {
            return error.InvalidValue;
        }
        if (cfg.interfaces.getPtr(m.out)) |itf| {
            if (itf.address == null) return error.InvalidValue;
        }
    }

    for (cfg.nat.port_forward) |f| {
        if (f.proto == .icmp) return error.InvalidValue;
        if (f.ext_port == 0) return error.InvalidValue;
        const to = types.parseIpPort(f.to) catch return error.InvalidValue;
        if (to.ip.isUnspecified() or to.ip.isMulticast() or
            to.ip.eql(types.Ipv4.limited_broadcast))
        {
            return error.InvalidValue;
        }
        if (f.in_iface) |in_iface| {
            if (!cfg.ports.contains(in_iface) and !cfg.interfaces.contains(in_iface)) {
                return error.UndefinedReference;
            }
            if (cfg.ports.contains(in_iface) and portInAnyBridge(cfg, in_iface)) {
                return error.InvalidValue;
            }
            if (cfg.interfaces.getPtr(in_iface)) |itf| {
                if (itf.bridge != null) return error.InvalidValue;
                if (itf.port == null) return error.InvalidValue;
            }
        }
    }
}

fn validateDhcp(cfg: *const schema.Config) ConfigError!void {
    for (cfg.dhcp) |d| {
        const itf = cfg.interfaces.getPtr(d.iface) orelse return error.UndefinedReference;
        const address = itf.address orelse return error.InvalidValue;
        if (std.mem.eql(u8, address, "dhcp")) return error.InvalidValue;

        const prefix = types.Prefix4.parse(address) catch return error.InvalidValue;
        const range = types.parseIpRange(d.pool) catch return error.InvalidValue;
        _ = types.parseDurationSeconds(d.lease) catch return error.InvalidValue;

        if (!prefix.contains(range.first) or !prefix.contains(range.last)) {
            return error.InvalidValue;
        }
        if (prefix.addr.value >= range.first.value and prefix.addr.value <= range.last.value) {
            return error.InvalidValue;
        }
        if (prefix.len < 31) {
            const network = prefix.network().value;
            const broadcast = network | ~prefix.mask();
            if (range.first.value == network or range.last.value == broadcast) {
                return error.InvalidValue;
            }
        }

        if (d.dns) |dns| {
            _ = types.Ipv4.parse(dns) catch return error.InvalidValue;
        }
        if (d.domain) |domain| {
            if (domain.len == 0 or domain.len > 255) return error.InvalidValue;
            for (domain) |c| {
                if (c == 0 or c == ' ') return error.InvalidValue;
            }
        }
        if (d.mtu) |mtu| {
            if (mtu < 576 or mtu > types.max_supported_mtu) return error.InvalidValue;
        }
        if (d.ntp) |ntp| {
            _ = types.Ipv4.parse(ntp) catch return error.InvalidValue;
        }

        for (d.reservations, 0..) |reservation, i| {
            const mac = types.Mac.parse(reservation.mac) catch return error.InvalidValue;
            const ip = types.Ipv4.parse(reservation.ip) catch return error.InvalidValue;
            if (mac.isZero() or mac.isMulticast() or mac.isBroadcast()) return error.InvalidValue;
            if (!prefix.contains(ip)) return error.InvalidValue;
            if (ip.eql(prefix.addr)) return error.InvalidValue;
            if (prefix.len < 31) {
                const network = prefix.network().value;
                const broadcast = network | ~prefix.mask();
                if (ip.value == network or ip.value == broadcast) return error.InvalidValue;
            }
            for (d.reservations[0..i]) |other| {
                if (std.mem.eql(u8, reservation.mac, other.mac)) return error.InvalidValue;
                if (std.mem.eql(u8, reservation.ip, other.ip)) return error.InvalidValue;
            }
        }
    }
}

fn validateDns(cfg: *const schema.Config) ConfigError!void {
    for (cfg.dns.upstreams) |upstream| {
        _ = types.Ipv4.parse(upstream) catch return error.InvalidValue;
    }
    if (cfg.dns.listen) |listen| {
        _ = types.Ipv4.parse(listen) catch return error.InvalidValue;
    } else if (cfg.dns.upstreams.len != 0 or cfg.dns.zones.len != 0) {
        return error.InvalidValue;
    }
    if (cfg.dns.max_entries == 0 or cfg.dns.max_entries > 1_000_000) {
        return error.InvalidValue;
    }
    for (cfg.dns.zones) |zone| {
        if (zone.suffix.len == 0 or zone.suffix.len > 255) return error.InvalidValue;
        if (zone.upstreams.len == 0) return error.InvalidValue;
        for (zone.upstreams) |upstream| {
            _ = types.Ipv4.parse(upstream) catch return error.InvalidValue;
        }
    }
    if (cfg.lease_db) |path| {
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) {
            return error.InvalidValue;
        }
    }
}

fn validatePortVlans(port: *const schema.PortConfig, vlan_aware: bool) ConfigError!void {
    if (!vlan_aware) {
        if (port.pvid != null or port.tagged.len != 0) return error.InvalidValue;
        return;
    }
    if (port.pvid) |pvid| {
        if (pvid == 0 or pvid > 4094) return error.InvalidValue;
    }
    for (port.tagged, 0..) |vlan, i| {
        if (vlan == 0 or vlan > 4094) return error.InvalidValue;
        for (port.tagged[0..i]) |seen| {
            if (seen == vlan) return error.InvalidValue;
        }
    }
}

fn portInAnyBridge(cfg: *const schema.Config, port_name: []const u8) bool {
    var it = cfg.bridges.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.ports) |member| {
            if (std.mem.eql(u8, member, port_name)) return true;
        }
    }
    return false;
}

// --- Tests ----------------------------------------------------------------

const example =
    \\{
    \\  "version": 1,
    \\  "instance": "travel-router",
    \\  "ports": {
    \\    "wan": { "kind": "l2", "device": "eth0" },
    \\    "lan": { "kind": "l2", "device": "eth1" }
    \\  },
    \\  "bridges": { "lan-br": { "ports": ["lan"] } },
    \\  "interfaces": {
    \\    "wan0": { "port": "wan", "address": "dhcp" },
    \\    "lan0": { "bridge": "lan-br", "address": "10.10.0.1/24" }
    \\  },
    \\  "routes": [
    \\    { "dst": "0.0.0.0/0", "via": "192.168.1.1", "dev": "wan0" }
    \\  ],
    \\  "nat": {
    \\    "masquerade": [ { "out": "wan0" } ],
    \\    "port_forward": [ { "proto": "tcp", "ext_port": 8080, "to": "10.10.0.10:80" } ]
    \\  },
    \\  "dhcp": [
    \\    { "iface": "lan0", "pool": "10.10.0.100-10.10.0.200" }
    \\  ],
    \\  "dns": { "upstreams": ["1.1.1.1"], "listen": "10.10.0.1" }
    \\}
;

test "valid config passes" {
    var parsed = try @import("parse.zig").parse(std.testing.allocator, example);
    defer parsed.deinit();
    try validate(&parsed.config);
}

test "rejects undefined bridge port" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["nope"] } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.UndefinedReference, validate(&parsed.config));
}

test "rejects l3 port in bridge" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "wan": { "kind": "l3", "device": "eth0" } },
        \\  "bridges": { "br": { "ports": ["wan"] } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects unsupported bridge options" {
    const input_stp =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["lan"], "stp": true } } }
    ;
    var parsed_stp = try @import("parse.zig").parse(std.testing.allocator, input_stp);
    defer parsed_stp.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed_stp.config));

    const input_vlan =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1", "pvid": 10, "tagged": [20] } },
        \\  "bridges": { "br": { "ports": ["lan"], "vlan_aware": true } } }
    ;
    var parsed_vlan = try @import("parse.zig").parse(std.testing.allocator, input_vlan);
    defer parsed_vlan.deinit();
    try validate(&parsed_vlan.config);

    const input_bad_vlan =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1", "pvid": 5000 } },
        \\  "bridges": { "br": { "ports": ["lan"], "vlan_aware": true } } }
    ;
    var parsed_bad_vlan = try @import("parse.zig").parse(std.testing.allocator, input_bad_vlan);
    defer parsed_bad_vlan.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed_bad_vlan.config));

    const input_offload =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["lan"], "offload": "kernel" } } }
    ;
    var parsed_offload = try @import("parse.zig").parse(std.testing.allocator, input_offload);
    defer parsed_offload.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed_offload.config));
}

test "rejects port in two bridges" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": {
        \\    "a": { "ports": ["lan"] },
        \\    "b": { "ports": ["lan"] } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects interface with both bridge and port" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "bridges": { "br": { "ports": ["lan"] } },
        \\  "interfaces": { "x": { "bridge": "br", "port": "lan" } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects dhcp pool outside subnet" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan0": { "port": "lan", "address": "10.10.0.1/24" } },
        \\  "dhcp": [ { "iface": "lan0", "pool": "10.20.0.10-10.20.0.20" } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects route without via or dev" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "routes": [ { "dst": "10.0.0.0/8" } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects cross-map duplicate name" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan": { "port": "lan" } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.DuplicateName, validate(&parsed.config));
}

test "rejects path separators in instance" {
    const input =
        \\{ "version": 1, "instance": "a/b" }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "accepts dhcp reservations and options" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan0": { "port": "lan", "address": "10.10.0.1/24" } },
        \\  "dhcp": [ {
        \\    "iface": "lan0", "pool": "10.10.0.100-10.10.0.200",
        \\    "domain": "lan.example", "mtu": 1400, "ntp": "10.10.0.1",
        \\    "reservations": [
        \\      { "mac": "02:00:00:00:00:02", "ip": "10.10.0.50" }
        \\    ] } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try validate(&parsed.config);
}

test "rejects duplicate dhcp reservations" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan0": { "port": "lan", "address": "10.10.0.1/24" } },
        \\  "dhcp": [ {
        \\    "iface": "lan0", "pool": "10.10.0.100-10.10.0.200",
        \\    "reservations": [
        \\      { "mac": "02:00:00:00:00:02", "ip": "10.10.0.50" },
        \\      { "mac": "02:00:00:00:00:02", "ip": "10.10.0.51" }
        \\    ] } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects dhcp reservation outside subnet" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan0": { "port": "lan", "address": "10.10.0.1/24" } },
        \\  "dhcp": [ {
        \\    "iface": "lan0", "pool": "10.10.0.100-10.10.0.200",
        \\    "reservations": [
        \\      { "mac": "02:00:00:00:00:02", "ip": "10.20.0.50" }
        \\    ] } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "accepts a lease database path" {
    const input =
        \\{ "version": 1, "instance": "x", "lease_db": "/var/lib/vnat/leases.json" }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try validate(&parsed.config);
}

test "rejects an empty lease database path" {
    const input =
        \\{ "version": 1, "instance": "x", "lease_db": "" }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects route via without a device" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "routes": [ { "dst": "0.0.0.0/0", "via": "10.0.0.1" } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects dhcp pool containing the router address" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "lan": { "kind": "l2", "device": "eth1" } },
        \\  "interfaces": { "lan0": { "port": "lan", "address": "10.10.0.1/24" } },
        \\  "dhcp": [ { "iface": "lan0", "pool": "10.10.0.1-10.10.0.20" } ] }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects duplicate port devices" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "eth1" },
        \\    "b": { "kind": "l2", "device": "eth1" } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.DuplicateName, validate(&parsed.config));
}

test "rejects existing l3 ports" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "wan": { "kind": "l3", "device": "eth0" } } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects zone-only dns without a listener" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "dns": { "zones": [ { "suffix": "lan", "upstreams": ["10.0.0.1"] } ] } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "rejects an outbound firewall policy that is not implemented" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "default_out": "drop" } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed.config));
}

test "accepts valid firewall rules" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": {
        \\    "lan": { "kind": "l2", "device": "eth1" },
        \\    "wan": { "kind": "l2", "device": "eth0" } },
        \\  "bridges": { "br": { "ports": ["lan"] } },
        \\  "interfaces": {
        \\    "lan0": { "bridge": "br", "address": "10.0.0.1/24" },
        \\    "wan0": { "port": "wan", "address": "dhcp" } },
        \\  "firewall": { "rules": [
        \\    { "action": "accept", "proto": "udp", "src": "10.0.0.0/24",
        \\      "dst": "1.1.1.1/32", "sport": 1024, "dport": 53,
        \\      "iif": "br", "oif": "wan0", "ct_state": "new" }
        \\  ] } }
    ;
    var parsed = try @import("parse.zig").parse(std.testing.allocator, input);
    defer parsed.deinit();
    try validate(&parsed.config);
}

test "rejects invalid firewall rules" {
    const bad_ref =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [ { "action": "drop", "iif": "nope" } ] } }
    ;
    var parsed_ref = try @import("parse.zig").parse(std.testing.allocator, bad_ref);
    defer parsed_ref.deinit();
    try std.testing.expectError(error.UndefinedReference, validate(&parsed_ref.config));

    const bad_port =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [
        \\    { "action": "drop", "proto": "icmp", "dport": 80 } ] } }
    ;
    var parsed_port = try @import("parse.zig").parse(std.testing.allocator, bad_port);
    defer parsed_port.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed_port.config));

    const bad_cidr =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [ { "action": "drop", "src": "10.0.0.0/33" } ] } }
    ;
    var parsed_cidr = try @import("parse.zig").parse(std.testing.allocator, bad_cidr);
    defer parsed_cidr.deinit();
    try std.testing.expectError(error.InvalidValue, validate(&parsed_cidr.config));
}
