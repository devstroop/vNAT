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
        if (port.create) |create| {
            switch (create) {
                .tun => if (port.kind != .l3) return error.InvalidValue,
                .tap => if (port.kind != .l2) return error.InvalidValue,
            }
        }
        if (port.mtu) |mtu| {
            if (mtu < 576 or mtu > 9000) return error.InvalidValue;
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

        for (bridge.ports, 0..) |port_name, i| {
            const port = cfg.ports.getPtr(port_name) orelse return error.UndefinedReference;
            if (port.kind != .l2) return error.InvalidValue;

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

        if (itf.bridge) |bridge| {
            if (!cfg.bridges.contains(bridge)) return error.UndefinedReference;
        }
        if (itf.port) |port| {
            if (!cfg.ports.contains(port)) return error.UndefinedReference;
            if (portInAnyBridge(cfg, port)) return error.InvalidValue;
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
        if (route.dev) |dev| {
            if (!cfg.ports.contains(dev) and !cfg.interfaces.contains(dev)) {
                return error.UndefinedReference;
            }
            if (cfg.ports.contains(dev) and portInAnyBridge(cfg, dev)) {
                return error.InvalidValue;
            }
        } else if (route.via == null) {
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
    }

    for (cfg.nat.port_forward) |f| {
        if (f.proto == .icmp) return error.InvalidValue;
        if (f.ext_port == 0) return error.InvalidValue;
        _ = types.parseIpPort(f.to) catch return error.InvalidValue;
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
    }
}

fn validateDns(cfg: *const schema.Config) ConfigError!void {
    for (cfg.dns.upstreams) |upstream| {
        _ = types.Ipv4.parse(upstream) catch return error.InvalidValue;
    }
    if (cfg.dns.listen) |listen| {
        _ = types.Ipv4.parse(listen) catch return error.InvalidValue;
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
    \\    "wan": { "kind": "l3", "device": "eth0" },
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
