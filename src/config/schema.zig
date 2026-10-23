//! Typed configuration model. Field names and defaults mirror the JSON schema
//! documented in docs/CORE-SCOPE.md.

const std = @import("std");

pub const LogLevel = enum { debug, info, warn, err };
pub const LogFormat = enum { text, json };

pub const LogConfig = struct {
    level: LogLevel = .info,
    format: LogFormat = .text,
};

pub const PortKind = enum { l2, l3 };

/// Create a virtual device instead of opening an existing interface.
pub const PortCreate = enum { tun, tap };

pub const PortConfig = struct {
    kind: PortKind,
    device: []const u8,
    create: ?PortCreate = null,
    mtu: ?u16 = null,
    /// Untagged ingress VLAN; null means untagged (non-VLAN bridge) or 1
    /// (VLAN-aware bridge).
    pvid: ?u16 = null,
    /// VLANs accepted and emitted with an 802.1Q tag on this port.
    tagged: []const u16 = &.{},
    /// Flooded frames (broadcast, multicast, unknown unicast) accepted from
    /// this port per second; zero disables storm control.
    storm_control: u32 = 1000,
};

pub const BridgeOffload = enum { none, kernel };

pub const BridgeConfig = struct {
    ports: []const []const u8,
    stp: bool = false,
    vlan_aware: bool = false,
    offload: BridgeOffload = .none,
};

pub const InterfaceConfig = struct {
    bridge: ?[]const u8 = null,
    port: ?[]const u8 = null,
    /// CIDR (e.g. "10.10.0.1/24") or "dhcp".
    address: ?[]const u8 = null,
    /// Routed VLAN on a VLAN-aware bridge SVI; defaults to 1.
    vlan: ?u16 = null,
};

pub const RouteConfig = struct {
    dst: []const u8,
    via: ?[]const u8 = null,
    dev: ?[]const u8 = null,
    metric: u32 = 0,
    table: u32 = 0,
};

pub const Proto = enum { tcp, udp, icmp };

pub const MasqueradeConfig = struct {
    out: []const u8,
};

pub const PortForwardConfig = struct {
    proto: Proto,
    ext_port: u16,
    to: []const u8,
    in_iface: ?[]const u8 = null,
};

pub const NatConfig = struct {
    masquerade: []const MasqueradeConfig = &.{},
    port_forward: []const PortForwardConfig = &.{},
};

pub const DhcpReservation = struct {
    mac: []const u8,
    ip: []const u8,
};

pub const DhcpConfig = struct {
    iface: []const u8,
    pool: []const u8,
    lease: []const u8 = "12h",
    dns: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    mtu: ?u16 = null,
    ntp: ?[]const u8 = null,
    reservations: []const DhcpReservation = &.{},
};

pub const DnsZone = struct {
    suffix: []const u8,
    upstreams: []const []const u8 = &.{},
};

pub const DnsConfig = struct {
    upstreams: []const []const u8 = &.{},
    cache: bool = true,
    listen: ?[]const u8 = null,
    max_entries: u32 = 1024,
    tcp: bool = true,
    zones: []const DnsZone = &.{},
};

pub const FirewallAction = enum { accept, drop, reject };

pub const FirewallCtState = enum { new, established, related, invalid };

pub const FirewallRuleConfig = struct {
    action: FirewallAction,
    proto: ?Proto = null,
    src: ?[]const u8 = null,
    dst: ?[]const u8 = null,
    sport: ?u16 = null,
    dport: ?u16 = null,
    iif: ?[]const u8 = null,
    oif: ?[]const u8 = null,
    ct_state: []const FirewallCtState = &.{},
};

pub const FirewallRateLimitConfig = struct {
    /// Generated ICMP errors per second; zero disables the limit.
    icmp: u32 = 100,
    /// ARP frames accepted per second.
    arp: u32 = 512,
    /// DHCP server requests per second.
    dhcp: u32 = 100,
};

pub const FirewallConfig = struct {
    default_in: FirewallAction = .drop,
    default_forward: FirewallAction = .drop,
    default_out: FirewallAction = .accept,
    rp_filter: bool = false,
    rate_limit: FirewallRateLimitConfig = .{},
    rules: []const FirewallRuleConfig = &.{},
};

pub const PortMap = std.StringArrayHashMapUnmanaged(PortConfig);
pub const BridgeMap = std.StringArrayHashMapUnmanaged(BridgeConfig);
pub const InterfaceMap = std.StringArrayHashMapUnmanaged(InterfaceConfig);

pub const Config = struct {
    version: u32,
    instance: []const u8,
    log: LogConfig = .{},
    ports: PortMap = .empty,
    bridges: BridgeMap = .empty,
    interfaces: InterfaceMap = .empty,
    routes: []const RouteConfig = &.{},
    nat: NatConfig = .{},
    dhcp: []const DhcpConfig = &.{},
    dns: DnsConfig = .{},
    firewall: FirewallConfig = .{},
    /// Optional path for the persistent DHCP lease database.
    lease_db: ?[]const u8 = null,
};
