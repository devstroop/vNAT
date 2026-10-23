//! Strict JSON config parser.
//!
//! Parsing is deliberately manual on top of `std.json.Value`: it gives precise
//! unknown-field rejection at every level and keeps the schema independent of
//! Zig's struct reflection. All strings are copied into an arena owned by the
//! returned `Parsed`, so the input buffer may be freed immediately.

const std = @import("std");
const schema = @import("schema.zig");
const types = @import("../types.zig");
const ConfigError = @import("../errors.zig").ConfigError;

pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    config: schema.Config,

    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
    }
};

pub fn parse(gpa: std.mem.Allocator, input: []const u8) ConfigError!Parsed {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    const root = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena.allocator(),
        input,
        .{ .allocate = .alloc_always },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };

    const config = try parseRoot(arena.allocator(), root);
    return .{ .arena = arena, .config = config };
}

const config_keys = [_][]const u8{
    "version", "instance", "log",  "ports", "bridges",  "interfaces",
    "routes",  "nat",      "dhcp", "dns",   "firewall", "lease_db",
};
const log_keys = [_][]const u8{ "level", "format" };
const port_keys = [_][]const u8{ "kind", "device", "create", "mtu", "pvid", "tagged", "storm_control" };
const bridge_keys = [_][]const u8{ "ports", "stp", "vlan_aware", "offload" };
const interface_keys = [_][]const u8{ "bridge", "port", "address", "vlan" };
const route_keys = [_][]const u8{ "dst", "via", "dev", "metric", "table" };
const nat_keys = [_][]const u8{ "masquerade", "port_forward" };
const masquerade_keys = [_][]const u8{"out"};
const forward_keys = [_][]const u8{ "proto", "ext_port", "to", "in" };
const dhcp_keys = [_][]const u8{
    "iface", "pool", "lease", "dns", "domain", "mtu", "ntp", "reservations",
};
const dhcp_reservation_keys = [_][]const u8{ "mac", "ip" };
const dns_zone_keys = [_][]const u8{ "suffix", "upstreams" };
const dns_keys = [_][]const u8{ "upstreams", "cache", "listen", "max_entries", "tcp", "zones" };
const firewall_keys = [_][]const u8{
    "default_in", "default_forward", "default_out", "rp_filter", "rate_limit", "rules",
};
const firewall_rate_keys = [_][]const u8{ "icmp", "arp", "dhcp" };
const firewall_rule_keys = [_][]const u8{
    "action", "proto", "src", "dst", "sport", "dport", "iif", "oif", "ct_state",
};

fn parseRoot(a: std.mem.Allocator, value: std.json.Value) ConfigError!schema.Config {
    const obj = try asObject(&value);
    try onlyKeys(obj, &config_keys);

    const version = try reqInt(u32, obj, "version");
    if (version != 1) return error.InvalidVersion;

    const instance = try reqString(obj, "instance");
    if (instance.len == 0) return error.InvalidValue;

    var config = schema.Config{ .version = version, .instance = instance };

    if (field(obj, "log")) |v| config.log = try parseLog(v);
    if (field(obj, "ports")) |v| config.ports = try parsePorts(a, v);
    if (field(obj, "bridges")) |v| config.bridges = try parseBridges(a, v);
    if (field(obj, "interfaces")) |v| config.interfaces = try parseInterfaces(a, v);
    if (field(obj, "routes")) |v| config.routes = try parseRoutes(a, v);
    if (field(obj, "nat")) |v| config.nat = try parseNat(a, v);
    if (field(obj, "dhcp")) |v| config.dhcp = try parseDhcp(a, v);
    if (field(obj, "dns")) |v| config.dns = try parseDns(a, v);
    if (field(obj, "firewall")) |v| config.firewall = try parseFirewall(a, v);
    config.lease_db = try optString(obj, "lease_db");

    return config;
}

fn parseLog(value: *const std.json.Value) ConfigError!schema.LogConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &log_keys);
    return .{
        .level = try optEnum(schema.LogLevel, obj, "level", .info),
        .format = try optEnum(schema.LogFormat, obj, "format", .text),
    };
}

fn parsePorts(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.PortMap {
    const obj = try asObject(value);
    var out: schema.PortMap = .empty;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const name = try a.dupe(u8, entry.key_ptr.*);
        if (name.len == 0) return error.InvalidValue;
        try out.put(a, name, try parsePort(a, entry.value_ptr));
    }
    return out;
}

fn parsePort(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.PortConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &port_keys);

    const device = try reqString(obj, "device");
    if (device.len == 0) return error.InvalidValue;

    const mtu: ?u16 = if (field(obj, "mtu")) |v| try asInt(u16, v) else null;
    if (mtu) |m| {
        if (m < 576 or m > types.max_supported_mtu) return error.InvalidValue;
    }

    const create: ?schema.PortCreate = if (field(obj, "create")) |v| blk: {
        const s = switch (v.*) {
            .string => |x| x,
            else => return error.InvalidType,
        };
        break :blk std.meta.stringToEnum(schema.PortCreate, s) orelse return error.InvalidValue;
    } else null;

    return .{
        .kind = try reqEnum(schema.PortKind, obj, "kind"),
        .device = device,
        .create = create,
        .mtu = mtu,
        .pvid = if (field(obj, "pvid")) |v| try asInt(u16, v) else null,
        .tagged = if (field(obj, "tagged")) |v| try parseIntArray(a, v) else &.{},
        .storm_control = try optInt(u32, obj, "storm_control", 1000),
    };
}

fn parseBridges(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.BridgeMap {
    const obj = try asObject(value);
    var out: schema.BridgeMap = .empty;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const name = try a.dupe(u8, entry.key_ptr.*);
        if (name.len == 0) return error.InvalidValue;
        try out.put(a, name, try parseBridge(a, entry.value_ptr));
    }
    return out;
}

fn parseBridge(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.BridgeConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &bridge_keys);
    return .{
        .ports = try reqStringArray(a, obj, "ports"),
        .stp = try optBool(obj, "stp", false),
        .vlan_aware = try optBool(obj, "vlan_aware", false),
        .offload = try optEnum(schema.BridgeOffload, obj, "offload", .none),
    };
}

fn parseInterfaces(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.InterfaceMap {
    const obj = try asObject(value);
    var out: schema.InterfaceMap = .empty;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const name = try a.dupe(u8, entry.key_ptr.*);
        if (name.len == 0) return error.InvalidValue;
        try out.put(a, name, try parseInterface(entry.value_ptr));
    }
    return out;
}

fn parseInterface(value: *const std.json.Value) ConfigError!schema.InterfaceConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &interface_keys);
    return .{
        .bridge = try optString(obj, "bridge"),
        .port = try optString(obj, "port"),
        .address = try optString(obj, "address"),
        .vlan = if (field(obj, "vlan")) |v| try asInt(u16, v) else null,
    };
}

fn parseRoutes(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const schema.RouteConfig {
    const arr = try asArray(value);
    const out = try a.alloc(schema.RouteConfig, arr.items.len);
    for (arr.items, 0..) |item, i| {
        out[i] = try parseRoute(&item);
    }
    return out;
}

fn parseRoute(value: *const std.json.Value) ConfigError!schema.RouteConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &route_keys);
    return .{
        .dst = try reqString(obj, "dst"),
        .via = try optString(obj, "via"),
        .dev = try optString(obj, "dev"),
        .metric = try optInt(u32, obj, "metric", 0),
        .table = try optInt(u32, obj, "table", 0),
    };
}

fn parseNat(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.NatConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &nat_keys);

    var nat = schema.NatConfig{};
    if (field(obj, "masquerade")) |v| nat.masquerade = try parseMasquerade(a, v);
    if (field(obj, "port_forward")) |v| nat.port_forward = try parseForwards(a, v);
    return nat;
}

fn parseMasquerade(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const schema.MasqueradeConfig {
    const arr = try asArray(value);
    const out = try a.alloc(schema.MasqueradeConfig, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = try asObject(&item);
        try onlyKeys(obj, &masquerade_keys);
        out[i] = .{ .out = try reqString(obj, "out") };
    }
    return out;
}

fn parseForwards(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const schema.PortForwardConfig {
    const arr = try asArray(value);
    const out = try a.alloc(schema.PortForwardConfig, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = try asObject(&item);
        try onlyKeys(obj, &forward_keys);
        out[i] = .{
            .proto = try reqEnum(schema.Proto, obj, "proto"),
            .ext_port = try reqInt(u16, obj, "ext_port"),
            .to = try reqString(obj, "to"),
            .in_iface = try optString(obj, "in"),
        };
    }
    return out;
}

fn parseDhcp(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const schema.DhcpConfig {
    const arr = try asArray(value);
    const out = try a.alloc(schema.DhcpConfig, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = try asObject(&item);
        try onlyKeys(obj, &dhcp_keys);
        out[i] = .{
            .iface = try reqString(obj, "iface"),
            .pool = try reqString(obj, "pool"),
            .lease = try optString(obj, "lease") orelse "12h",
            .dns = try optString(obj, "dns"),
            .domain = try optString(obj, "domain"),
            .mtu = if (field(obj, "mtu")) |v| try asInt(u16, v) else null,
            .ntp = try optString(obj, "ntp"),
            .reservations = if (field(obj, "reservations")) |v|
                try parseDhcpReservations(a, v)
            else
                &.{},
        };
    }
    return out;
}

fn parseDhcpReservations(
    a: std.mem.Allocator,
    value: *const std.json.Value,
) ConfigError![]const schema.DhcpReservation {
    const arr = try asArray(value);
    const out = try a.alloc(schema.DhcpReservation, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = try asObject(&item);
        try onlyKeys(obj, &dhcp_reservation_keys);
        out[i] = .{
            .mac = try reqString(obj, "mac"),
            .ip = try reqString(obj, "ip"),
        };
    }
    return out;
}

fn parseDnsZones(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]schema.DnsZone {
    const arr = try asArray(value);
    const zones = try a.alloc(schema.DnsZone, arr.items.len);
    for (arr.items, 0..) |*item, i| {
        const obj = try asObject(item);
        try onlyKeys(obj, &dns_zone_keys);
        zones[i] = .{
            .suffix = try reqString(obj, "suffix"),
            .upstreams = if (field(obj, "upstreams")) |v| try parseStringArray(a, v) else &.{},
        };
    }
    return zones;
}

fn parseDns(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.DnsConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &dns_keys);
    return .{
        .upstreams = if (field(obj, "upstreams")) |v| try parseStringArray(a, v) else &.{},
        .cache = try optBool(obj, "cache", true),
        .listen = try optString(obj, "listen"),
        .max_entries = try optInt(u32, obj, "max_entries", 1024),
        .tcp = try optBool(obj, "tcp", true),
        .zones = if (field(obj, "zones")) |v| try parseDnsZones(a, v) else &.{},
    };
}

fn parseFirewall(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.FirewallConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &firewall_keys);
    var firewall = schema.FirewallConfig{
        .default_in = try optEnum(schema.FirewallAction, obj, "default_in", .drop),
        .default_forward = try optEnum(schema.FirewallAction, obj, "default_forward", .drop),
        .default_out = try optEnum(schema.FirewallAction, obj, "default_out", .accept),
        .rp_filter = try optBool(obj, "rp_filter", false),
        .rate_limit = if (field(obj, "rate_limit")) |rate_value|
            try parseFirewallRate(rate_value)
        else
            .{},
    };
    if (field(obj, "rules")) |rules_value| {
        const arr = try asArray(rules_value);
        const rules = try a.alloc(schema.FirewallRuleConfig, arr.items.len);
        for (arr.items, 0..) |item, i| rules[i] = try parseFirewallRule(a, &item);
        firewall.rules = rules;
    }
    return firewall;
}

fn parseFirewallRate(value: *const std.json.Value) ConfigError!schema.FirewallRateLimitConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &firewall_rate_keys);
    const default = schema.FirewallRateLimitConfig{};
    return .{
        .icmp = try optInt(u32, obj, "icmp", default.icmp),
        .arp = try optInt(u32, obj, "arp", default.arp),
        .dhcp = try optInt(u32, obj, "dhcp", default.dhcp),
    };
}

fn parseFirewallRule(a: std.mem.Allocator, value: *const std.json.Value) ConfigError!schema.FirewallRuleConfig {
    const obj = try asObject(value);
    try onlyKeys(obj, &firewall_rule_keys);
    return .{
        .action = try reqEnum(schema.FirewallAction, obj, "action"),
        .proto = if (field(obj, "proto")) |v| blk: {
            const s = switch (v.*) {
                .string => |x| x,
                else => return error.InvalidType,
            };
            break :blk std.meta.stringToEnum(schema.Proto, s) orelse return error.InvalidValue;
        } else null,
        .src = try optString(obj, "src"),
        .dst = try optString(obj, "dst"),
        .sport = if (field(obj, "sport")) |v| try asInt(u16, v) else null,
        .dport = if (field(obj, "dport")) |v| try asInt(u16, v) else null,
        .iif = try optString(obj, "iif"),
        .oif = try optString(obj, "oif"),
        .ct_state = if (field(obj, "ct_state")) |v| try parseCtStates(a, v) else &.{},
    };
}

fn parseCtStates(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const schema.FirewallCtState {
    switch (value.*) {
        .string => |one| {
            const states = try a.alloc(schema.FirewallCtState, 1);
            states[0] = std.meta.stringToEnum(schema.FirewallCtState, one) orelse
                return error.InvalidValue;
            return states;
        },
        .array => |arr| {
            const states = try a.alloc(schema.FirewallCtState, arr.items.len);
            for (arr.items, 0..) |item, i| {
                const s = switch (item) {
                    .string => |x| x,
                    else => return error.InvalidType,
                };
                states[i] = std.meta.stringToEnum(schema.FirewallCtState, s) orelse
                    return error.InvalidValue;
            }
            return states;
        },
        else => return error.InvalidType,
    }
}

// --- JSON helpers ---------------------------------------------------------

fn asObject(value: *const std.json.Value) ConfigError!*const std.json.ObjectMap {
    return switch (value.*) {
        .object => &value.object,
        else => error.NotAnObject,
    };
}

fn asArray(value: *const std.json.Value) ConfigError!*const std.json.Array {
    return switch (value.*) {
        .array => &value.array,
        else => error.InvalidType,
    };
}

fn field(obj: *const std.json.ObjectMap, key: []const u8) ?*const std.json.Value {
    return obj.getPtr(key);
}

fn onlyKeys(obj: *const std.json.ObjectMap, allowed: []const []const u8) ConfigError!void {
    var it = obj.iterator();
    while (it.next()) |entry| {
        var found = false;
        for (allowed) |k| {
            if (std.mem.eql(u8, k, entry.key_ptr.*)) {
                found = true;
                break;
            }
        }
        if (!found) return error.UnknownField;
    }
}

fn reqString(obj: *const std.json.ObjectMap, key: []const u8) ConfigError![]const u8 {
    const v = field(obj, key) orelse return error.MissingField;
    return switch (v.*) {
        .string => |s| s,
        else => error.InvalidType,
    };
}

fn optString(obj: *const std.json.ObjectMap, key: []const u8) ConfigError!?[]const u8 {
    const v = field(obj, key) orelse return null;
    return switch (v.*) {
        .string => |s| s,
        else => error.InvalidType,
    };
}

fn asInt(comptime T: type, value: *const std.json.Value) ConfigError!T {
    return switch (value.*) {
        .integer => |n| std.math.cast(T, n) orelse error.InvalidValue,
        .number_string => |s| std.fmt.parseInt(T, s, 10) catch error.InvalidValue,
        else => error.InvalidType,
    };
}

fn reqInt(comptime T: type, obj: *const std.json.ObjectMap, key: []const u8) ConfigError!T {
    const v = field(obj, key) orelse return error.MissingField;
    return asInt(T, v);
}

fn optInt(comptime T: type, obj: *const std.json.ObjectMap, key: []const u8, default: T) ConfigError!T {
    const v = field(obj, key) orelse return default;
    return asInt(T, v);
}

fn optBool(obj: *const std.json.ObjectMap, key: []const u8, default: bool) ConfigError!bool {
    const v = field(obj, key) orelse return default;
    return switch (v.*) {
        .bool => |b| b,
        else => error.InvalidType,
    };
}

fn reqEnum(comptime E: type, obj: *const std.json.ObjectMap, key: []const u8) ConfigError!E {
    const s = try reqString(obj, key);
    return std.meta.stringToEnum(E, s) orelse error.InvalidValue;
}

fn optEnum(comptime E: type, obj: *const std.json.ObjectMap, key: []const u8, default: E) ConfigError!E {
    const v = field(obj, key) orelse return default;
    const s = switch (v.*) {
        .string => |s| s,
        else => return error.InvalidType,
    };
    return std.meta.stringToEnum(E, s) orelse error.InvalidValue;
}

fn reqStringArray(a: std.mem.Allocator, obj: *const std.json.ObjectMap, key: []const u8) ConfigError![]const []const u8 {
    const v = field(obj, key) orelse return error.MissingField;
    return parseStringArray(a, v);
}

fn parseIntArray(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const u16 {
    const arr = try asArray(value);
    const out = try a.alloc(u16, arr.items.len);
    for (arr.items, 0..) |item, i| out[i] = try asInt(u16, &item);
    return out;
}

fn parseStringArray(a: std.mem.Allocator, value: *const std.json.Value) ConfigError![]const []const u8 {
    const arr = try asArray(value);
    const out = try a.alloc([]const u8, arr.items.len);
    for (arr.items, 0..) |item, i| {
        out[i] = switch (item) {
            .string => |s| s,
            else => return error.InvalidType,
        };
    }
    return out;
}

// --- Tests ----------------------------------------------------------------

const example =
    \\{
    \\  "version": 1,
    \\  "instance": "travel-router",
    \\  "log": { "level": "debug", "format": "text" },
    \\  "ports": {
    \\    "wan": { "kind": "l2", "device": "eth0" },
    \\    "lan": { "kind": "l2", "device": "eth1", "mtu": 1500, "storm_control": 250 }
    \\  },
    \\  "bridges": {
    \\    "lan-br": { "ports": ["lan"], "stp": false }
    \\  },
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
    \\    { "iface": "lan0", "pool": "10.10.0.100-10.10.0.200", "lease": "12h", "dns": "10.10.0.1" }
    \\  ],
    \\  "dns": { "upstreams": ["1.1.1.1", "8.8.8.8"], "cache": true, "listen": "10.10.0.1" },
    \\  "firewall": {
    \\    "default_in": "drop", "default_forward": "drop", "default_out": "accept",
    \\    "rp_filter": true,
    \\    "rate_limit": { "icmp": 50, "arp": 256, "dhcp": 25 },
    \\    "rules": [
    \\      { "action": "accept", "proto": "tcp", "src": "10.10.0.0/24",
    \\        "dst": "0.0.0.0/0", "dport": 443, "iif": "lan-br",
    \\        "ct_state": ["new", "established"] }
    \\    ]
    \\  }
    \\}
;

test "parses a full config" {
    var parsed = try parse(std.testing.allocator, example);
    defer parsed.deinit();

    const cfg = &parsed.config;
    try std.testing.expectEqual(@as(u32, 1), cfg.version);
    try std.testing.expectEqualStrings("travel-router", cfg.instance);
    try std.testing.expectEqual(@as(usize, 2), cfg.ports.count());
    try std.testing.expectEqual(schema.PortKind.l2, cfg.ports.get("wan").?.kind);
    try std.testing.expectEqual(@as(u32, 1000), cfg.ports.get("wan").?.storm_control);
    try std.testing.expectEqual(@as(u32, 250), cfg.ports.get("lan").?.storm_control);
    try std.testing.expectEqual(@as(usize, 1), cfg.bridges.count());
    try std.testing.expectEqual(@as(usize, 1), cfg.routes.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.nat.masquerade.len);
    try std.testing.expectEqual(@as(usize, 2), cfg.dns.upstreams.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.dhcp.len);
    try std.testing.expectEqualStrings("12h", cfg.dhcp[0].lease);
    try std.testing.expect(cfg.firewall.rp_filter);
    try std.testing.expectEqual(@as(u32, 50), cfg.firewall.rate_limit.icmp);
    try std.testing.expectEqual(@as(u32, 256), cfg.firewall.rate_limit.arp);
    try std.testing.expectEqual(@as(u32, 25), cfg.firewall.rate_limit.dhcp);
    try std.testing.expectEqual(@as(usize, 1), cfg.firewall.rules.len);
    try std.testing.expectEqual(schema.FirewallAction.accept, cfg.firewall.rules[0].action);
    try std.testing.expectEqual(schema.Proto.tcp, cfg.firewall.rules[0].proto.?);
    try std.testing.expectEqual(@as(u16, 443), cfg.firewall.rules[0].dport.?);
    try std.testing.expectEqual(@as(usize, 2), cfg.firewall.rules[0].ct_state.len);
}

test "rejects unknown top-level field" {
    const input =
        \\{ "version": 1, "instance": "x", "bogus": true }
    ;
    try std.testing.expectError(error.UnknownField, parse(std.testing.allocator, input));
}

test "rejects unknown nested field" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "ports": { "p": { "kind": "l3", "device": "eth0", "magic": 1 } } }
    ;
    try std.testing.expectError(error.UnknownField, parse(std.testing.allocator, input));
}

test "rejects invalid json" {
    try std.testing.expectError(error.InvalidJson, parse(std.testing.allocator, "{"));
}

test "rejects missing fields and bad version" {
    try std.testing.expectError(error.MissingField, parse(std.testing.allocator,
        \\{ "version": 1 }
    ));
    try std.testing.expectError(error.InvalidVersion, parse(std.testing.allocator,
        \\{ "version": 2, "instance": "x" }
    ));
}

test "rejects wrong types" {
    try std.testing.expectError(error.InvalidType, parse(std.testing.allocator,
        \\{ "version": "1", "instance": "x" }
    ));
}

test "parses firewall rate limits and rejects unknown keys" {
    const input =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rate_limit": { "icmp": 0, "arp": 10 } } }
    ;
    var parsed = try parse(std.testing.allocator, input);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u32, 0), parsed.config.firewall.rate_limit.icmp);
    try std.testing.expectEqual(@as(u32, 10), parsed.config.firewall.rate_limit.arp);
    try std.testing.expectEqual(@as(u32, 100), parsed.config.firewall.rate_limit.dhcp);

    const bad =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rate_limit": { "dns": 10 } } }
    ;
    try std.testing.expectError(error.UnknownField, parse(std.testing.allocator, bad));
}

test "rejects invalid firewall values" {
    const bad_proto =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [ { "action": "accept", "proto": "sctp" } ] } }
    ;
    try std.testing.expectError(error.InvalidValue, parse(std.testing.allocator, bad_proto));

    const bad_ct =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [ { "action": "drop", "ct_state": ["bogus"] } ] } }
    ;
    try std.testing.expectError(error.InvalidValue, parse(std.testing.allocator, bad_ct));

    const bad_action =
        \\{ "version": 1, "instance": "x",
        \\  "firewall": { "rules": [ { "action": "log" } ] } }
    ;
    try std.testing.expectError(error.InvalidValue, parse(std.testing.allocator, bad_action));
}
