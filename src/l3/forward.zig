//! IPv4 forwarding pipeline for L2 ports.
//!
//! The forwarder is deliberately synchronous and allocation-free on the frame
//! path: one immutable frame in, at most one frame out. Control-plane state
//! (FIB, local addresses, ARP cache) is read without locks; R3 swaps snapshots
//! in from the control plane.

const std = @import("std");
const types = @import("../types.zig");
const port_mod = @import("../port/port.zig");
const schema = @import("../config/schema.zig");
const ethernet = @import("../l2/ethernet.zig");
const stp = @import("../l2/stp.zig");
const ipv4 = @import("ipv4.zig");
const arp = @import("arp.zig");
const icmp = @import("icmp.zig");
const fib = @import("fib.zig");
const conntrack_mod = @import("../nat/conntrack.zig");
const nat_mod = @import("../nat/nat.zig");
const dhcp_message = @import("../services/dhcp/message.zig");
const dhcp_server = @import("../services/dhcp/server.zig");
const memory_port = @import("../port/memory.zig");
const rate = @import("rate.zig");

const PortError = @import("../errors.zig").PortError;

pub const conntrack_default_entries: u32 = 65_536;
pub const conntrack_small_entries: u32 = 4_096;

pub const arp_ttl_ms: i64 = 300_000;
pub const arp_request_interval_ms: i64 = 1_000;
pub const arp_pending_ttl_ms: i64 = 1_000;
const arp_miss_max_entries: usize = 1024;
const pending_slots = 32;
const pending_packet_max = 1600;
const fdb_max_entries: usize = 4096;
const fdb_ttl_ms: i64 = 300_000;
const maintenance_interval_ms: i64 = 1_000;
const dhcp_failed_retry_ms: i64 = 30_000;
const dhcp_probe_delay_ms: i64 = 250;
const dhcp_pending_slots = 32;
const dhcp_reply_max = 576;

const PendingPacket = struct {
    used: bool = false,
    port: types.PortId = .{ .value = 0 },
    next_hop: types.Ipv4 = .{ .value = 0 },
    vlan: u16 = 0,
    queued_ms: i64 = 0,
    len: u16 = 0,
    bytes: [pending_packet_max]u8 = undefined,
};

pub const PortEntry = struct {
    id: types.PortId,
    config_name: []const u8,
    port: port_mod.Port,
};

pub const LocalAddr = struct {
    prefix: types.Prefix4,
    port: types.PortId,
    vlan: u16 = 0,
};

pub const Counters = struct {
    rx_frames: u64 = 0,
    forwarded: u64 = 0,
    bridged: u64 = 0,
    local_delivered: u64 = 0,
    dropped: u64 = 0,
    arp_requests: u64 = 0,
    arp_replies: u64 = 0,
    garps: u64 = 0,
    icmp_errors: u64 = 0,
    pending_queued: u64 = 0,
    pending_flushed: u64 = 0,
    pending_dropped: u64 = 0,
    snat_packets: u64 = 0,
    dnat_packets: u64 = 0,
    icmp_translated: u64 = 0,
    dhcp_requests: u64 = 0,
    dhcp_offers: u64 = 0,
    dhcp_acks: u64 = 0,
    dhcp_naks: u64 = 0,
    dhcp_dropped: u64 = 0,
    dhcp_conflicts: u64 = 0,
    dhcp_client_bound: u64 = 0,
    nat_unsupported: u64 = 0,
    firewall_dropped: u64 = 0,
    firewall_spoofed: u64 = 0,
    storm_dropped: u64 = 0,
    stp_bpdus_rx: u64 = 0,
    stp_bpdus_tx: u64 = 0,
    stp_filtered: u64 = 0,
    stp_invalid: u64 = 0,
    icmp_rate_limited: u64 = 0,
    arp_rate_limited: u64 = 0,
    dhcp_rate_limited: u64 = 0,
};

pub const BridgePortVlan = struct {
    pvid: u16 = 0,
    tagged: []const u16 = &.{},
};

pub const StpPortState = enum { blocking, listening, learning, forwarding };
pub const StpPortRole = enum { disabled, root, designated, alternate };

pub const StpPort = struct {
    port_id: u16,
    cost: u32 = stp.default_port_cost,
    role: StpPortRole = .disabled,
    state: StpPortState = .blocking,
    rx: ?stp.Bpdu = null,
    rx_at_ms: i64 = 0,
    state_deadline_ms: i64 = 0,
};

pub const Bridge = struct {
    id: u32,
    members: []types.PortId,
    vlan_aware: bool = false,
    vlans: []BridgePortVlan = &.{},
    stp: bool = false,
    stp_ports: []StpPort = &.{},
    stp_bridge_id: u64 = 0,
    stp_root_id: u64 = 0,
    stp_root_cost: u32 = 0,
    stp_root_age_ms: u32 = 0,
    stp_root_port: ?usize = null,
    stp_last_hello_ms: i64 = -1,

    pub fn contains(self: Bridge, port: types.PortId) bool {
        for (self.members) |member| {
            if (member.eql(port)) return true;
        }
        return false;
    }

    pub fn portVlan(self: Bridge, port: types.PortId) ?BridgePortVlan {
        for (self.members, 0..) |member, i| {
            if (member.eql(port)) {
                if (i >= self.vlans.len) return null;
                return self.vlans[i];
            }
        }
        return null;
    }

    pub fn allowsTagged(self: Bridge, port: types.PortId, vlan: u16) bool {
        const cfg = self.portVlan(port) orelse return false;
        for (cfg.tagged) |tagged| {
            if (tagged == vlan) return true;
        }
        return false;
    }
};

const FdbEntry = struct {
    port: types.PortId,
    updated_ms: i64,
};

fn stpPortIndex(bridge: Bridge, port: types.PortId) ?usize {
    for (bridge.members, 0..) |member, i| {
        if (member.eql(port)) return if (i < bridge.stp_ports.len) i else null;
    }
    return null;
}

fn stpPortState(bridge: Bridge, port: types.PortId) ?StpPortState {
    const index = stpPortIndex(bridge, port) orelse return null;
    return bridge.stp_ports[index].state;
}

fn stpRecompute(bridge: *Bridge, now: i64) void {
    if (!bridge.stp) return;
    var best_root = bridge.stp_bridge_id;
    var best_cost: u32 = 0;
    var best_bridge = bridge.stp_bridge_id;
    var best_port: u16 = 0;
    var best_index: ?usize = null;

    for (bridge.stp_ports, 0..) |port, i| {
        const rx = port.rx orelse continue;
        const elapsed: u64 = @intCast(@max(@as(i64, 0), now - port.rx_at_ms));
        if (@as(u64, rx.message_age_ms) + elapsed > rx.max_age_ms) continue;
        const cost = rx.root_cost +| port.cost;
        if (best_index == null or stp.vectorLess(
            rx.root_id,
            cost,
            rx.bridge_id,
            rx.port_id,
            best_root,
            best_cost,
            best_bridge,
            best_port,
        )) {
            best_root = rx.root_id;
            best_cost = cost;
            best_bridge = rx.bridge_id;
            best_port = rx.port_id;
            best_index = i;
        }
    }
    bridge.stp_root_id = best_root;
    bridge.stp_root_cost = best_cost;
    bridge.stp_root_port = best_index;
    bridge.stp_root_age_ms = if (best_index) |i| blk: {
        const port = bridge.stp_ports[i];
        const elapsed: u64 = @intCast(@max(@as(i64, 0), now - port.rx_at_ms));
        const age = @as(u64, port.rx.?.message_age_ms) + elapsed;
        break :blk @intCast(@min(age, std.math.maxInt(u32)));
    } else 0;

    for (bridge.stp_ports, 0..) |*port, i| {
        if (port.rx) |rx| {
            const elapsed: u64 = @intCast(@max(@as(i64, 0), now - port.rx_at_ms));
            if (@as(u64, rx.message_age_ms) + elapsed > rx.max_age_ms) port.rx = null;
        }
        const is_root = best_index == i;
        var designated = true;
        if (!is_root) {
            if (port.rx) |rx| {
                const elapsed: u64 = @intCast(@max(@as(i64, 0), now - port.rx_at_ms));
                const age = @as(u64, rx.message_age_ms) + elapsed;
                const our_cost = bridge.stp_root_cost +| port.cost;
                if (age <= rx.max_age_ms and stp.vectorLess(
                    rx.root_id,
                    rx.root_cost,
                    rx.bridge_id,
                    rx.port_id,
                    bridge.stp_root_id,
                    our_cost,
                    bridge.stp_bridge_id,
                    port.port_id,
                )) designated = false;
            }
        }

        const next_role = if (is_root)
            StpPortRole.root
        else if (!designated)
            StpPortRole.alternate
        else
            StpPortRole.designated;
        const role_changed = port.role != next_role;
        port.role = next_role;

        if (port.role == .alternate) {
            port.state = .blocking;
            port.state_deadline_ms = 0;
            continue;
        }
        if (role_changed and port.state != .blocking) {
            port.state = .listening;
            port.state_deadline_ms = now + stp.forward_delay_ms;
        }
        switch (port.state) {
            .blocking => {
                port.state = .listening;
                port.state_deadline_ms = now + stp.forward_delay_ms;
            },
            .listening => if (now >= port.state_deadline_ms) {
                port.state = .learning;
                port.state_deadline_ms = now + stp.forward_delay_ms;
            },
            .learning => if (now >= port.state_deadline_ms) {
                port.state = .forwarding;
                port.state_deadline_ms = 0;
            },
            .forwarding => {},
        }
    }
}

const FirewallIface = union(enum) {
    port: types.PortId,
    bridge: u32,
};

const FirewallRule = struct {
    action: schema.FirewallAction,
    proto: ?u8 = null,
    src: ?types.Prefix4 = null,
    dst: ?types.Prefix4 = null,
    sport: ?u16 = null,
    dport: ?u16 = null,
    iif: ?FirewallIface = null,
    oif: ?FirewallIface = null,
    ct_mask: u8 = 0,
    packets: u64 = 0,
};

pub const DhcpClientState = enum {
    init,
    selecting,
    requesting,
    bound,
    renewing,
    rebinding,
    failed,
};

const PendingDhcpOffer = struct {
    used: bool = false,
    port: types.PortId = .{ .value = 0 },
    bridge: ?u32 = null,
    vlan: u16 = 0,
    client_mac: types.Mac = .{},
    ip: types.Ipv4 = .{},
    queued_ms: i64 = 0,
    len: u16 = 0,
    dst_ip: types.Ipv4 = .{},
    dst_mac: types.Mac = .{},
    bytes: [dhcp_reply_max]u8 = undefined,
};

pub const DhcpClient = struct {
    port: types.PortId,
    mac: types.Mac,
    state: DhcpClientState = .init,
    xid: u32 = 0,
    server_ip: ?types.Ipv4 = null,
    offered_ip: ?types.Ipv4 = null,
    subnet_mask: ?types.Ipv4 = null,
    router: ?types.Ipv4 = null,
    lease_seconds: u32 = 0,
    renew_seconds: u32 = 0,
    rebind_seconds: u32 = 0,
    renew_at_ms: i64 = 0,
    rebind_at_ms: i64 = 0,
    lease_expires_ms: i64 = 0,
    last_sent_ms: i64 = 0,
    attempts: u8 = 0,
    configured: bool = false,
    want_masquerade: bool = false,
    configured_prefix: ?types.Prefix4 = null,
    configured_router: ?types.Ipv4 = null,
};

pub const Forwarder = struct {
    gpa: std.mem.Allocator,
    ports: []const PortEntry,
    fib: fib.Fib = .{},
    arp: arp.Cache = .{},
    local: std.ArrayListUnmanaged(LocalAddr) = .empty,
    arp_misses: std.AutoHashMapUnmanaged(u32, i64) = .empty,
    pending: [pending_slots]PendingPacket = @splat(.{}),
    conntrack: conntrack_mod.Conntrack,
    snat_rules: std.ArrayListUnmanaged(nat_mod.Rule) = .empty,
    forward_rules: std.ArrayListUnmanaged(nat_mod.ForwardRule) = .empty,
    firewall_rules: std.ArrayListUnmanaged(FirewallRule) = .empty,
    dhcp_servers: std.ArrayListUnmanaged(dhcp_server.Server) = .empty,
    dhcp_clients: std.ArrayListUnmanaged(DhcpClient) = .empty,
    dhcp_pending: [dhcp_pending_slots]PendingDhcpOffer = @splat(.{}),
    storm_limiters: []rate.Limiter = &.{},
    bridges: std.ArrayListUnmanaged(Bridge) = .empty,
    fdb: std.AutoHashMapUnmanaged(u128, FdbEntry) = .empty,
    last_maintenance_ms: i64 = 0,
    icmp_limiter: rate.Limiter = .{},
    arp_limiter: rate.Limiter = .{},
    dhcp_limiter: rate.Limiter = .{},
    firewall: schema.FirewallConfig = .{
        .default_in = .accept,
        .default_forward = .accept,
        .default_out = .accept,
    },
    counters: Counters = .{},

    pub fn init(gpa: std.mem.Allocator, ports: []const PortEntry) PortError!Forwarder {
        return initInner(gpa, ports, conntrack_small_entries);
    }

    fn initInner(
        gpa: std.mem.Allocator,
        ports: []const PortEntry,
        conntrack_entries: u32,
    ) PortError!Forwarder {
        var self = Forwarder{
            .gpa = gpa,
            .ports = ports,
            .conntrack = try conntrack_mod.Conntrack.init(gpa, conntrack_entries),
        };
        errdefer self.conntrack.deinit();
        try self.arp.reserve(gpa, 64);
        errdefer self.arp.deinit(gpa);
        try self.arp_misses.ensureTotalCapacity(gpa, arp_miss_max_entries);
        errdefer self.arp_misses.deinit(gpa);
        self.storm_limiters = try gpa.alloc(rate.Limiter, ports.len);
        for (self.storm_limiters) |*limiter| limiter.* = rate.Limiter.init(0);
        return self;
    }

    pub fn deinit(self: *Forwarder) void {
        self.fib.deinit(self.gpa);
        self.arp.deinit(self.gpa);
        self.local.deinit(self.gpa);
        self.arp_misses.deinit(self.gpa);
        self.snat_rules.deinit(self.gpa);
        self.forward_rules.deinit(self.gpa);
        self.firewall_rules.deinit(self.gpa);
        for (self.dhcp_servers.items) |*server| server.deinit();
        self.dhcp_servers.deinit(self.gpa);
        self.dhcp_clients.deinit(self.gpa);
        if (self.storm_limiters.len != 0) self.gpa.free(self.storm_limiters);
        for (self.bridges.items) |bridge| {
            for (bridge.vlans) |vlan| self.gpa.free(vlan.tagged);
            self.gpa.free(bridge.vlans);
            self.gpa.free(bridge.members);
            if (bridge.stp_ports.len != 0) self.gpa.free(bridge.stp_ports);
        }
        self.bridges.deinit(self.gpa);
        self.fdb.deinit(self.gpa);
        self.conntrack.deinit();
    }

    pub fn addLocal(
        self: *Forwarder,
        prefix: types.Prefix4,
        port: types.PortId,
        vlan: u16,
    ) PortError!void {
        try self.local.append(self.gpa, .{ .prefix = prefix, .port = port, .vlan = vlan });
    }

    fn removeLocal(self: *Forwarder, prefix: types.Prefix4, port: types.PortId, vlan: u16) void {
        for (self.local.items, 0..) |local, i| {
            if (local.port.eql(port) and local.vlan == vlan and
                local.prefix.len == prefix.len and local.prefix.addr.eql(prefix.addr))
            {
                _ = self.local.swapRemove(i);
                return;
            }
        }
    }

    pub fn addRoute(self: *Forwarder, route: fib.Route) PortError!void {
        try self.fib.add(self.gpa, route);
    }

    pub fn addSnatRule(self: *Forwarder, port: types.PortId, addr: types.Ipv4) PortError!void {
        for (self.snat_rules.items) |*rule| {
            if (rule.port.eql(port)) {
                rule.addr = addr;
                return;
            }
        }
        try self.snat_rules.append(self.gpa, .{ .port = port, .addr = addr });
    }

    fn removeSnatRule(self: *Forwarder, port: types.PortId) void {
        for (self.snat_rules.items, 0..) |rule, i| {
            if (rule.port.eql(port)) {
                _ = self.snat_rules.swapRemove(i);
                return;
            }
        }
    }

    pub fn addForwardRule(
        self: *Forwarder,
        proto: u8,
        ext_port: u16,
        to_addr: types.Ipv4,
        to_port: u16,
    ) PortError!void {
        return self.addForwardRuleOn(proto, ext_port, to_addr, to_port, null);
    }

    pub fn addForwardRuleOn(
        self: *Forwarder,
        proto: u8,
        ext_port: u16,
        to_addr: types.Ipv4,
        to_port: u16,
        ingress: ?types.PortId,
    ) PortError!void {
        try self.forward_rules.append(self.gpa, .{
            .proto = proto,
            .ext_port = ext_port,
            .to_addr = to_addr,
            .to_port = to_port,
            .ingress = ingress,
        });
    }

    pub fn dhcpServers(self: *Forwarder) []dhcp_server.Server {
        return self.dhcp_servers.items;
    }

    pub fn addDhcpServer(self: *Forwarder, cfg: dhcp_server.Config) PortError!void {
        const server = dhcp_server.Server.init(self.gpa, cfg) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidArgument,
        };
        try self.dhcp_servers.append(self.gpa, server);
    }

    pub fn addDhcpClient(
        self: *Forwarder,
        io: std.Io,
        port: types.PortId,
        mac: types.Mac,
        want_masquerade: bool,
    ) PortError!void {
        try self.dhcp_clients.append(self.gpa, .{
            .port = port,
            .mac = mac,
            .xid = newDhcpXid(io),
            .want_masquerade = want_masquerade,
        });
    }

    pub fn hasDhcpClient(self: *const Forwarder, port: types.PortId) bool {
        for (self.dhcp_clients.items) |client| {
            if (client.port.eql(port)) return true;
        }
        return false;
    }

    fn portMac(self: *const Forwarder, port: types.PortId) types.Mac {
        for (self.ports) |entry| {
            if (entry.id.eql(port)) return entry.port.info().mac;
        }
        return .{};
    }

    pub fn tick(self: *Forwarder, io: std.Io) void {
        const now = nowMs(io);
        if (now - self.conntrack.last_gc_ms >= conntrack_mod.gc_interval_ms) {
            self.conntrack.gc(now);
        }
        if (now - self.last_maintenance_ms >= maintenance_interval_ms) {
            self.arp.prune(now, arp_ttl_ms);
            self.pruneFdb(now);
            self.last_maintenance_ms = now;
        }
        for (self.dhcp_servers.items) |*server| server.gc(now);
        self.tickDhcpOffers(io, now);
        self.tickDhcpClients(io, now);
        self.stpTick(io, now);
    }

    pub fn fromConfig(
        gpa: std.mem.Allocator,
        io: std.Io,
        cfg: *const schema.Config,
        ports: []const PortEntry,
    ) PortError!Forwarder {
        var self = try initInner(gpa, ports, conntrack_default_entries);
        errdefer self.deinit();
        self.firewall = cfg.firewall;
        self.icmp_limiter = rate.Limiter.init(cfg.firewall.rate_limit.icmp);
        self.arp_limiter = rate.Limiter.init(cfg.firewall.rate_limit.arp);
        self.dhcp_limiter = rate.Limiter.init(cfg.firewall.rate_limit.dhcp);
        for (self.ports, 0..) |entry, i| {
            if (cfg.ports.get(entry.config_name)) |port_cfg| {
                self.storm_limiters[i] = rate.Limiter.init(port_cfg.storm_control);
            }
        }

        var bridge_it = cfg.bridges.iterator();
        var bridge_id: u32 = 0;
        while (bridge_it.next()) |bridge_entry| {
            const bridge_cfg = bridge_entry.value_ptr;
            if (bridge_cfg.ports.len == 0) return error.InvalidArgument;
            const offload = bridge_cfg.offload == .kernel;
            const userspace_stp = bridge_cfg.stp and !offload;
            var synthetic_name = [_][]const u8{bridge_entry.key_ptr.*};
            const member_names: []const []const u8 = if (offload)
                synthetic_name[0..]
            else
                bridge_cfg.ports;
            const members = try gpa.alloc(types.PortId, member_names.len);
            errdefer gpa.free(members);
            const vlans = try gpa.alloc(BridgePortVlan, member_names.len);
            errdefer gpa.free(vlans);
            const stp_ports: []StpPort = if (userspace_stp)
                try gpa.alloc(StpPort, member_names.len)
            else
                &.{};
            errdefer if (userspace_stp) gpa.free(stp_ports);
            var bridge_mac = types.Mac{};
            var vlan_count: usize = 0;
            errdefer for (vlans[0..vlan_count]) |vlan| gpa.free(vlan.tagged);
            for (member_names, 0..) |port_name, i| {
                const port_entry = findPort(ports, port_name) orelse return error.NotFound;
                members[i] = port_entry.id;
                if (userspace_stp) {
                    const mac = port_entry.port.info().mac;
                    if (!mac.isZero() and
                        (bridge_mac.isZero() or std.mem.order(u8, &mac.bytes, &bridge_mac.bytes) == .lt))
                    {
                        bridge_mac = mac;
                    }
                }
                if (bridge_cfg.vlan_aware) {
                    const tagged = if (offload)
                        try offloadTrunkVlans(gpa, cfg, bridge_entry.key_ptr.*, bridge_cfg.*)
                    else blk: {
                        const port_cfg = cfg.ports.getPtr(port_name) orelse return error.NotFound;
                        break :blk try gpa.dupe(u16, port_cfg.tagged);
                    };
                    vlans[i] = .{
                        .pvid = if (offload) 1 else (cfg.ports.getPtr(port_name) orelse
                            return error.NotFound).pvid orelse 1,
                        .tagged = tagged,
                    };
                    vlan_count = i + 1;
                } else {
                    vlans[i] = .{};
                }
            }
            if (userspace_stp) {
                if (bridge_mac.isZero()) {
                    bridge_mac = .{ .bytes = .{
                        0x02,
                        0,
                        0,
                        @truncate(bridge_id >> 16),
                        @truncate(bridge_id >> 8),
                        @truncate(bridge_id),
                    } };
                }
                for (stp_ports, 0..) |*port, i| {
                    port.* = .{ .port_id = @intCast((i + 1) << 8) };
                }
            }
            const stp_bridge_id = if (userspace_stp)
                stp.bridgeId(stp.default_priority, bridge_mac)
            else
                0;
            try self.bridges.append(gpa, .{
                .id = bridge_id,
                .members = members,
                .vlan_aware = bridge_cfg.vlan_aware,
                .vlans = vlans,
                .stp = userspace_stp,
                .stp_ports = stp_ports,
                .stp_bridge_id = stp_bridge_id,
                .stp_root_id = stp_bridge_id,
            });
            bridge_id += 1;
        }

        var it = cfg.interfaces.iterator();
        while (it.next()) |entry| {
            const itf = entry.value_ptr.*;
            const address = itf.address orelse continue;

            if (itf.bridge) |bridge_name| {
                const bridge = self.bridgeByName(cfg, bridge_name) orelse return error.NotFound;
                if (std.mem.eql(u8, address, "dhcp")) return error.InvalidArgument;
                const prefix = types.Prefix4.parse(address) catch return error.InvalidArgument;
                const vlan = if (bridge.vlan_aware) itf.vlan orelse 1 else 0;
                for (bridge.members) |member| try self.addLocal(prefix, member, vlan);
                try self.addRoute(.{
                    .prefix = .{ .addr = prefix.network(), .len = prefix.len },
                    .port = bridge.members[0],
                    .bridge = bridge.id,
                    .vlan = vlan,
                    .kind = .connected,
                });
                continue;
            }

            const port_name = itf.port orelse continue;
            const port_entry = findPort(ports, port_name) orelse return error.NotFound;
            if (std.mem.eql(u8, address, "dhcp")) {
                var want_masquerade = false;
                for (cfg.nat.masquerade) |masquerade| {
                    if (std.mem.eql(u8, masquerade.out, entry.key_ptr.*) or
                        std.mem.eql(u8, masquerade.out, port_name))
                    {
                        want_masquerade = true;
                        break;
                    }
                }
                try self.addDhcpClient(
                    io,
                    port_entry.id,
                    port_entry.port.info().mac,
                    want_masquerade,
                );
                continue;
            }

            const prefix = types.Prefix4.parse(address) catch return error.InvalidArgument;
            try self.addLocal(prefix, port_entry.id, 0);
            try self.addRoute(.{
                .prefix = .{ .addr = prefix.network(), .len = prefix.len },
                .port = port_entry.id,
                .kind = .connected,
            });
        }

        for (cfg.routes) |route| {
            const dst = types.Prefix4.parse(route.dst) catch return error.InvalidArgument;
            const next_hop: ?types.Ipv4 = if (route.via) |via|
                types.Ipv4.parse(via) catch return error.InvalidArgument
            else
                null;
            const dev = route.dev orelse return error.InvalidArgument;
            var port_entry = findRoutePort(cfg, ports, dev) orelse null;
            var route_bridge: ?u32 = null;
            var route_vlan: u16 = 0;
            if (cfg.interfaces.get(dev)) |itf| {
                if (itf.bridge) |bridge_name| {
                    const bridge = self.bridgeByName(cfg, bridge_name) orelse return error.NotFound;
                    port_entry = self.portById(bridge.members[0]) orelse return error.NotFound;
                    route_bridge = bridge.id;
                    route_vlan = if (bridge.vlan_aware) itf.vlan orelse 1 else 0;
                }
            }
            const endpoint = port_entry orelse return error.NotFound;

            try self.addRoute(.{
                .prefix = .{ .addr = dst.network(), .len = dst.len },
                .next_hop = next_hop,
                .port = endpoint.id,
                .bridge = route_bridge,
                .vlan = route_vlan,
                .metric = route.metric,
            });
        }

        for (cfg.nat.masquerade) |masquerade| {
            const rule = resolveMasquerade(cfg, self.local.items, ports, masquerade.out) orelse {
                // Defer SNAT rule installation until a DHCP client on this port
                // obtains a lease.
                const out_name = masquerade.out;
                if (cfg.interfaces.get(out_name)) |itf| {
                    if (itf.address != null and std.mem.eql(u8, itf.address.?, "dhcp")) {
                        continue;
                    }
                }
                // Also allow port-name references that already have a client.
                if (findPort(ports, masquerade.out)) |port_entry| {
                    if (self.hasDhcpClient(port_entry.id)) continue;
                }
                return error.InvalidArgument;
            };
            try self.addSnatRule(rule.port, rule.addr);
        }

        for (cfg.nat.port_forward) |forward| {
            const to = types.parseIpPort(forward.to) catch return error.InvalidArgument;
            const proto: u8 = switch (forward.proto) {
                .tcp => 6,
                .udp => 17,
                .icmp => return error.InvalidArgument,
            };
            const ingress = if (forward.in_iface) |name| blk: {
                const port_entry = findRoutePort(cfg, ports, name) orelse return error.NotFound;
                break :blk port_entry.id;
            } else null;
            try self.addForwardRuleOn(proto, forward.ext_port, to.ip, to.port, ingress);
        }

        for (cfg.dhcp) |dhcp| {
            const itf = cfg.interfaces.getPtr(dhcp.iface) orelse return error.InvalidArgument;
            var port_entry: PortEntry = undefined;
            var server_bridge: ?u32 = null;
            var server_vlan: u16 = 0;
            if (itf.bridge) |bridge_name| {
                const bridge = self.bridgeByName(cfg, bridge_name) orelse return error.NotFound;
                port_entry = self.portById(bridge.members[0]) orelse return error.NotFound;
                server_bridge = bridge.id;
                server_vlan = if (bridge.vlan_aware) itf.vlan orelse 1 else 0;
            } else {
                const port_name = itf.port orelse return error.InvalidArgument;
                port_entry = findPort(ports, port_name) orelse return error.NotFound;
            }
            const address = itf.address orelse return error.InvalidArgument;
            if (std.mem.eql(u8, address, "dhcp")) return error.InvalidArgument;

            const prefix = types.Prefix4.parse(address) catch return error.InvalidArgument;
            const pool = types.parseIpRange(dhcp.pool) catch return error.InvalidArgument;
            const lease_seconds = types.parseDurationSeconds(dhcp.lease) catch
                return error.InvalidArgument;
            const dns = if (dhcp.dns) |dns_text|
                types.Ipv4.parse(dns_text) catch return error.InvalidArgument
            else
                prefix.addr;
            const ntp: ?types.Ipv4 = if (dhcp.ntp) |ntp_text|
                types.Ipv4.parse(ntp_text) catch return error.InvalidArgument
            else
                null;

            var reservations: std.ArrayListUnmanaged(dhcp_server.Reservation) = .empty;
            defer reservations.deinit(self.gpa);
            for (dhcp.reservations) |reservation| {
                try reservations.append(self.gpa, .{
                    .mac = types.Mac.parse(reservation.mac) catch return error.InvalidArgument,
                    .ip = types.Ipv4.parse(reservation.ip) catch return error.InvalidArgument,
                });
            }

            try self.addDhcpServer(.{
                .port = port_entry.id,
                .bridge = server_bridge,
                .vlan = server_vlan,
                .server_ip = prefix.addr,
                .prefix = prefix,
                .pool = pool,
                .lease_seconds = lease_seconds,
                .dns = dns,
                .domain = dhcp.domain,
                .mtu = dhcp.mtu,
                .ntp = ntp,
                .reservations = reservations.items,
            });
        }

        try self.compileFirewall(cfg);
        return self;
    }

    pub const FirewallHook = enum { input, forward, output };

    pub const FirewallProbe = struct {
        proto: u8,
        src: types.Ipv4,
        dst: types.Ipv4,
        sport: ?u16 = null,
        dport: ?u16 = null,
        iif: ?[]const u8 = null,
        oif: ?[]const u8 = null,
        state: schema.FirewallCtState = .new,
        hook: FirewallHook = .forward,
    };

    pub const FirewallProbeResult = struct {
        /// Zero-based rule index, or null when the default policy applies.
        rule: ?usize,
        action: schema.FirewallAction,
    };

    /// Evaluates a synthetic packet against the compiled rule set. Intended for
    /// `vnat firewall test`; it never touches a real port.
    pub fn probeFirewallConfig(
        gpa: std.mem.Allocator,
        io: std.Io,
        cfg: *const schema.Config,
        probe: FirewallProbe,
    ) PortError!FirewallProbeResult {
        const port_count = cfg.ports.count();
        const dummy_ports = try gpa.alloc(memory_port.MemoryPort, port_count);
        defer gpa.free(dummy_ports);
        const entries = try gpa.alloc(PortEntry, port_count);
        defer gpa.free(entries);

        var it = cfg.ports.iterator();
        var i: usize = 0;
        while (it.next()) |entry| : (i += 1) {
            const id = types.PortId{ .value = @intCast(i + 1) };
            dummy_ports[i] = memory_port.MemoryPort.init(
                gpa,
                id,
                entry.key_ptr.*,
                entry.value_ptr.mtu orelse 1500,
            );
            entries[i] = .{
                .id = id,
                .config_name = entry.key_ptr.*,
                .port = dummy_ports[i].port(),
            };
        }

        var fwd = try Forwarder.fromConfig(gpa, io, cfg, entries);
        defer fwd.deinit();

        const iif = if (probe.iif) |name|
            fwd.probeIfacePort(cfg, name) orelse return error.NotFound
        else
            types.PortId.invalid;
        const oif = if (probe.oif) |name|
            fwd.probeIfacePort(cfg, name) orelse return error.NotFound
        else
            null;

        var l4: [4]u8 = .{ 0, 0, 0, 0 };
        if (probe.sport) |port| std.mem.writeInt(u16, l4[0..2], port, .big);
        if (probe.dport) |port| std.mem.writeInt(u16, l4[2..4], port, .big);
        const ip = ipv4.Header{
            .header_len = 20,
            .total_len = 24,
            .id = 0,
            .flags_frag = 0,
            .ttl = 64,
            .protocol = probe.proto,
            .src = probe.src,
            .dst = probe.dst,
            .payload = &l4,
            .packet = &l4,
        };

        if (fwd.firewallMatch(iif, oif, ip, probe.state)) |matched| {
            return .{ .rule = matched.index, .action = matched.action };
        }
        return .{
            .rule = null,
            .action = switch (probe.hook) {
                .input => cfg.firewall.default_in,
                .forward => cfg.firewall.default_forward,
                .output => cfg.firewall.default_out,
            },
        };
    }

    fn probeIfacePort(
        self: *const Forwarder,
        cfg: *const schema.Config,
        name: []const u8,
    ) ?types.PortId {
        const iface = self.firewallIface(cfg, name) orelse return null;
        return switch (iface) {
            .port => |id| id,
            .bridge => |bridge_id| blk: {
                const bridge = self.bridgeById(bridge_id) orelse break :blk null;
                if (bridge.members.len == 0) break :blk null;
                break :blk bridge.members[0];
            },
        };
    }

    /// Sends a gratuitous ARP request for every local address so peers refresh
    /// their neighbor caches after an address change or daemon restart.
    pub fn announce(self: *Forwarder, io: std.Io) PortError!void {
        for (self.local.items) |local| {
            const entry = self.portById(local.port) orelse continue;
            const info = entry.port.info();
            if (info.kind == .tun or info.mac.isZero()) continue;

            var payload: [28]u8 = undefined;
            _ = arp.write(
                &payload,
                .request,
                info.mac,
                local.prefix.addr,
                types.Mac.zero,
                local.prefix.addr,
            ) catch continue;
            self.sendL2Vlan(
                io,
                local.port,
                types.Mac.broadcast,
                ethernet.EtherType.arp,
                &payload,
                local.vlan,
            ) catch continue;
            self.counters.garps += 1;
        }
    }

    pub fn handle(
        self: *Forwarder,
        io: std.Io,
        frame: []const u8,
        ingress: types.PortId,
    ) PortError!void {
        return self.handleAt(io, frame, ingress, nowMs(io));
    }

    fn handleAt(
        self: *Forwarder,
        io: std.Io,
        frame: []const u8,
        ingress: types.PortId,
        now: i64,
    ) PortError!void {
        self.counters.rx_frames += 1;
        self.gcPending(now);
        if (now - self.conntrack.last_gc_ms >= conntrack_mod.gc_interval_ms) {
            self.conntrack.gc(now);
        }

        const ingress_entry = self.portById(ingress) orelse {
            self.counters.dropped += 1;
            return;
        };
        if (ingress_entry.port.info().kind == .tun) {
            const ip = ipv4.parse(frame) catch {
                self.counters.dropped += 1;
                return;
            };
            try self.handleIpv4(io, null, ip, ingress, 0);
            return;
        }

        const eth = ethernet.parse(frame) catch {
            self.counters.dropped += 1;
            return;
        };

        const bridge = self.bridgeForPort(ingress);
        if (eth.dst.eql(stp.multicast)) {
            if (bridge) |b| {
                if (b.stp) self.handleStp(b.id, ingress, eth.payload, now);
            }
            return;
        }
        const vlan: u16 = if (bridge) |b|
            self.ingressVlan(b, ingress, eth.vlan) orelse {
                self.counters.dropped += 1;
                return;
            }
        else blk: {
            if (eth.vlan != null) {
                self.counters.dropped += 1;
                return;
            }
            break :blk 0;
        };

        if (bridge) |b| {
            if (b.stp) {
                const state = stpPortState(b, ingress) orelse .blocking;
                if (state != .learning and state != .forwarding) {
                    self.counters.stp_filtered += 1;
                    self.counters.dropped += 1;
                    return;
                }
            }
            if (!eth.src.isMulticast() and !eth.src.isZero()) {
                self.learnFdb(b.id, vlan, eth.src, ingress, now);
            }
            if (b.stp and stpPortState(b, ingress) == .learning) return;
        }

        switch (eth.ethertype) {
            ethernet.EtherType.arp => {
                try self.handleArp(io, eth, ingress, vlan);
                if (bridge) |b| {
                    if (!self.bridgeMacLocal(b, eth.dst)) {
                        try self.bridgeForward(io, b, frame, eth, ingress, vlan, now);
                    }
                }
            },
            ethernet.EtherType.ipv4 => {
                if (bridge) |b| {
                    if (!eth.dst.isMulticast() and !self.bridgeMacLocal(b, eth.dst)) {
                        try self.bridgeForward(io, b, frame, eth, ingress, vlan, now);
                        return;
                    }
                }
                const ip = ipv4.parse(eth.payload) catch {
                    self.counters.dropped += 1;
                    return;
                };
                try self.handleIpv4(io, eth, ip, ingress, vlan);
                if (bridge) |b| {
                    if (eth.dst.isMulticast()) {
                        try self.bridgeForward(io, b, frame, eth, ingress, vlan, now);
                    }
                }
            },
            else => {
                if (bridge) |b| {
                    try self.bridgeForward(io, b, frame, eth, ingress, vlan, now);
                } else {
                    self.counters.dropped += 1;
                }
            },
        }
    }

    fn ingressVlan(self: *const Forwarder, bridge: Bridge, port: types.PortId, tagged: ?u16) ?u16 {
        _ = self;
        if (!bridge.vlan_aware) {
            if (tagged != null) return null;
            return 0;
        }
        const cfg = bridge.portVlan(port) orelse return null;
        if (tagged) |vlan| {
            if (bridge.allowsTagged(port, vlan)) return vlan;
            return null;
        }
        return cfg.pvid;
    }

    fn bridgeMacLocal(self: *const Forwarder, bridge: Bridge, mac: types.Mac) bool {
        for (bridge.members) |member| {
            if (self.portMac(member).eql(mac)) return true;
        }
        return false;
    }

    fn learnFdb(self: *Forwarder, bridge_id: u32, vlan: u16, mac: types.Mac, port: types.PortId, now: i64) void {
        const key = fdbKey(bridge_id, vlan, mac);
        if (self.fdb.getPtr(key)) |slot| {
            slot.* = .{ .port = port, .updated_ms = now };
            return;
        }
        if (self.fdb.count() >= fdb_max_entries) {
            var oldest_key: u128 = 0;
            var oldest_ms: i64 = std.math.maxInt(i64);
            var it = self.fdb.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.updated_ms < oldest_ms) {
                    oldest_ms = entry.value_ptr.updated_ms;
                    oldest_key = entry.key_ptr.*;
                }
            }
            _ = self.fdb.remove(oldest_key);
        }
        self.fdb.put(self.gpa, key, .{ .port = port, .updated_ms = now }) catch {};
    }

    fn handleStp(
        self: *Forwarder,
        bridge_id: u32,
        ingress: types.PortId,
        payload: []const u8,
        now: i64,
    ) void {
        const bridge: *Bridge = for (self.bridges.items) |*item| {
            if (item.id == bridge_id) break item;
        } else return;
        if (!bridge.stp) return;
        const index = stpPortIndex(bridge.*, ingress) orelse return;
        const bpdu = stp.parse(payload) catch {
            self.counters.stp_invalid += 1;
            return;
        };
        if (bpdu.bridge_id == bridge.stp_bridge_id) return;
        bridge.stp_ports[index].rx = bpdu;
        bridge.stp_ports[index].rx_at_ms = now;
        self.counters.stp_bpdus_rx += 1;
        stpRecompute(bridge, now);
    }

    fn stpTick(self: *Forwarder, io: std.Io, now: i64) void {
        for (self.bridges.items) |*bridge| {
            if (!bridge.stp) continue;
            stpRecompute(bridge, now);
            if (bridge.stp_last_hello_ms >= 0 and
                now - bridge.stp_last_hello_ms < stp.hello_ms) continue;
            for (bridge.stp_ports, 0..) |port, i| {
                if (port.role != .designated) continue;
                self.sendStpBpdu(io, bridge, i);
            }
            bridge.stp_last_hello_ms = now;
        }
    }

    fn sendStpBpdu(self: *Forwarder, io: std.Io, bridge: *const Bridge, index: usize) void {
        const port = bridge.stp_ports[index];
        const member = bridge.members[index];
        const entry = self.portById(member) orelse return;
        if (entry.port.info().kind == .tun) return;

        var payload: [stp.payload_len]u8 = undefined;
        _ = stp.write(&payload, .{
            .root_id = bridge.stp_root_id,
            .root_cost = bridge.stp_root_cost,
            .bridge_id = bridge.stp_bridge_id,
            .port_id = port.port_id,
            .message_age_ms = bridge.stp_root_age_ms,
            .max_age_ms = stp.max_age_ms,
            .hello_ms = stp.hello_ms,
            .forward_delay_ms = stp.forward_delay_ms,
        }) catch return;

        var frame: [64]u8 = undefined;
        const hlen = ethernet.write(
            &frame,
            stp.multicast,
            stp.idMac(bridge.stp_bridge_id),
            @intCast(stp.payload_len),
            null,
        ) catch return;
        @memcpy(frame[hlen..][0..stp.payload_len], &payload);
        entry.port.write(io, frame[0 .. hlen + stp.payload_len]) catch {
            self.counters.dropped += 1;
            return;
        };
        self.counters.stp_bpdus_tx += 1;
    }

    fn bridgeForward(
        self: *Forwarder,
        io: std.Io,
        bridge: Bridge,
        frame: []const u8,
        eth: ethernet.Header,
        ingress: types.PortId,
        vlan: u16,
        now: i64,
    ) PortError!void {
        _ = frame;
        const multicast = eth.dst.isMulticast();
        if (!multicast) {
            if (self.fdb.get(fdbKey(bridge.id, vlan, eth.dst))) |entry| {
                if (!entry.port.eql(ingress)) {
                    self.sendBridgeFrame(io, bridge, entry.port, eth, vlan) catch {
                        self.counters.dropped += 1;
                    };
                }
                return;
            }
        }
        if (!self.stormAllow(ingress, now)) {
            self.counters.storm_dropped += 1;
            self.counters.dropped += 1;
            return;
        }
        // A down or misconfigured member must not stop the flood to the
        // remaining members.
        for (bridge.members) |member| {
            if (member.eql(ingress)) continue;
            self.sendBridgeFrame(io, bridge, member, eth, vlan) catch {
                self.counters.dropped += 1;
                continue;
            };
        }
        if (multicast) self.learnFdb(bridge.id, vlan, eth.src, ingress, now);
    }

    fn stormAllow(self: *Forwarder, port: types.PortId, now: i64) bool {
        for (self.ports, 0..) |entry, i| {
            if (entry.id.eql(port)) return self.storm_limiters[i].allow(now);
        }
        return true;
    }

    const EgressVlan = union(enum) { untagged, tagged: u16, filtered };

    fn egressVlan(bridge: Bridge, port: types.PortId, vlan: u16) EgressVlan {
        if (!bridge.vlan_aware) return .untagged;
        const cfg = bridge.portVlan(port) orelse return .filtered;
        for (cfg.tagged) |tagged| {
            if (tagged == vlan) return .{ .tagged = vlan };
        }
        if (cfg.pvid == vlan) return .untagged;
        return .filtered;
    }

    fn sendBridgeFrame(
        self: *Forwarder,
        io: std.Io,
        bridge: Bridge,
        member: types.PortId,
        eth: ethernet.Header,
        vlan: u16,
    ) PortError!void {
        if (bridge.stp and stpPortState(bridge, member) != .forwarding) return;
        const tag: ?u16 = switch (egressVlan(bridge, member, vlan)) {
            .untagged => null,
            .tagged => |vid| vid,
            .filtered => return,
        };
        const entry = self.portById(member) orelse return error.NotFound;
        const info = entry.port.info();
        if (info.kind == .tun) return;

        var out: [2048]u8 = undefined;
        const hlen = ethernet.write(&out, eth.dst, eth.src, eth.ethertype, tag) catch
            return error.FrameTooLarge;
        if (eth.payload.len > out.len - hlen) return error.FrameTooLarge;
        if (eth.payload.len > info.mtu) return error.FrameTooLarge;
        @memcpy(out[hlen..][0..eth.payload.len], eth.payload);
        try entry.port.write(io, out[0 .. hlen + eth.payload.len]);
        self.counters.bridged += 1;
    }

    fn pruneFdb(self: *Forwarder, now: i64) void {
        var it = self.fdb.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.updated_ms > fdb_ttl_ms) self.fdb.removeByPtr(entry.key_ptr);
        }
    }

    fn handleArp(
        self: *Forwarder,
        io: std.Io,
        eth: ethernet.Header,
        ingress: types.PortId,
        vlan: u16,
    ) PortError!void {
        const packet = arp.parse(eth.payload) catch {
            self.counters.dropped += 1;
            return;
        };
        if (packet.sender_mac.isMulticast()) return;

        const entry = self.portById(ingress) orelse {
            self.counters.dropped += 1;
            return;
        };
        const info = entry.port.info();
        if (!self.arp_limiter.allow(nowMs(io))) {
            self.counters.arp_rate_limited += 1;
            return;
        }

        const learned = !packet.sender_ip.isUnspecified() and !packet.sender_mac.isZero();
        if (learned) {
            self.arp.putVlan(self.gpa, packet.sender_ip, vlan, .{
                .mac = packet.sender_mac,
                .port = ingress,
                .updated_ms = nowMs(io),
            }) catch {};
            _ = self.arp_misses.remove(packet.sender_ip.value);
        }

        if (packet.operation == .request) {
            if (self.localOn(packet.target_ip, ingress, vlan)) |local| {
                if (!info.mac.isZero()) {
                    var reply: [28]u8 = undefined;
                    _ = arp.write(
                        &reply,
                        .reply,
                        info.mac,
                        local.prefix.addr,
                        packet.sender_mac,
                        packet.sender_ip,
                    ) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                    try self.sendL2Vlan(io, ingress, packet.sender_mac, ethernet.EtherType.arp, &reply, vlan);
                    self.counters.arp_replies += 1;
                }
            }
        }

        if (learned) {
            try self.flushPending(io, ingress, packet.sender_ip, packet.sender_mac, vlan);
        }
    }

    fn tickDhcpClients(self: *Forwarder, io: std.Io, now: i64) void {
        for (self.dhcp_clients.items) |*client| {
            switch (client.state) {
                .init => self.beginDhcpSelection(io, client),
                .selecting => {
                    if (client.attempts >= 10) {
                        client.state = .failed;
                        client.last_sent_ms = now;
                        continue;
                    }
                    const delay: i64 = if (client.attempts == 0) 0 else @min(@as(i64, 1000) << @intCast(@min(client.attempts, 6)), 8000);
                    if (now - client.last_sent_ms >= delay) {
                        self.sendDhcpClientMessage(io, client, .discover, null) catch {};
                        client.attempts += 1;
                        client.last_sent_ms = now;
                    }
                },
                .requesting => {
                    if (client.attempts >= 10) {
                        self.beginDhcpSelection(io, client);
                        continue;
                    }
                    const delay: i64 = if (client.attempts == 0) 0 else @min(@as(i64, 1000) << @intCast(@min(client.attempts, 6)), 8000);
                    if (now - client.last_sent_ms >= delay) {
                        self.sendDhcpClientMessage(io, client, .request, client.offered_ip) catch {};
                        client.attempts += 1;
                        client.last_sent_ms = now;
                    }
                },
                .bound, .renewing, .rebinding => self.tickDhcpLease(io, client, now),
                .failed => {
                    // The uplink may appear after boot (common on travel
                    // routers). Retry selection periodically instead of
                    // waiting for a process restart.
                    if (now - client.last_sent_ms >= dhcp_failed_retry_ms) {
                        self.beginDhcpSelection(io, client);
                    }
                },
            }
        }
    }

    fn tickDhcpLease(self: *Forwarder, io: std.Io, client: *DhcpClient, now: i64) void {
        if (client.lease_expires_ms != 0 and now >= client.lease_expires_ms) {
            self.clearDhcpClient(client);
            self.beginDhcpSelection(io, client);
            return;
        }

        if (client.state == .bound and client.renew_at_ms != 0 and now >= client.renew_at_ms) {
            client.state = .renewing;
            client.xid = newDhcpXid(io);
            client.attempts = 0;
            client.last_sent_ms = 0;
        }
        if (client.state != .rebinding and client.rebind_at_ms != 0 and now >= client.rebind_at_ms) {
            client.state = .rebinding;
            client.xid = newDhcpXid(io);
            client.attempts = 0;
            client.last_sent_ms = 0;
        }

        if (client.state != .renewing and client.state != .rebinding) return;
        if (client.attempts >= 10) return;
        const delay: i64 = if (client.attempts == 0) 0 else @min(@as(i64, 1000) << @intCast(@min(client.attempts, 6)), 8000);
        if (now - client.last_sent_ms < delay) return;
        self.sendDhcpClientMessage(io, client, .request, null) catch {};
        client.attempts += 1;
        client.last_sent_ms = now;
    }

    fn beginDhcpSelection(self: *Forwarder, io: std.Io, client: *DhcpClient) void {
        _ = self;
        client.state = .selecting;
        client.xid = newDhcpXid(io);
        client.attempts = 0;
        client.last_sent_ms = 0;
        client.server_ip = null;
        client.offered_ip = null;
    }

    fn clearDhcpClient(self: *Forwarder, client: *DhcpClient) void {
        if (client.configured_prefix) |prefix| {
            self.removeLocal(prefix, client.port, 0);
            _ = self.fib.remove(.{ .addr = prefix.network(), .len = prefix.len }, client.port);
        }
        if (client.configured_router) |router| {
            self.removeDefaultRoute(client.port, router);
        }
        if (client.want_masquerade) self.removeSnatRule(client.port);

        client.configured = false;
        client.configured_prefix = null;
        client.configured_router = null;
        client.offered_ip = null;
        client.subnet_mask = null;
        client.router = null;
        client.lease_seconds = 0;
        client.renew_seconds = 0;
        client.rebind_seconds = 0;
        client.renew_at_ms = 0;
        client.rebind_at_ms = 0;
        client.lease_expires_ms = 0;
    }

    fn removeDefaultRoute(self: *Forwarder, port: types.PortId, next_hop: types.Ipv4) void {
        for (self.fib.routes.items, 0..) |route, i| {
            if (route.prefix.len != 0 or !route.port.eql(port)) continue;
            if (route.next_hop) |hop| {
                if (hop.eql(next_hop)) {
                    _ = self.fib.routes.swapRemove(i);
                    return;
                }
            }
        }
    }

    fn handleDhcpClient(
        self: *Forwarder,
        io: std.Io,
        ip: ipv4.Header,
        ingress: types.PortId,
        now: i64,
    ) PortError!bool {
        if (ip.protocol != ipv4.Protocol.udp) return false;
        if (ip.payload.len < 8) return false;
        const udp_len = readU16(ip.payload, 4);
        if (udp_len < 8 or udp_len > ip.payload.len) return false;
        if (readU16(ip.payload, 0) != 67 or readU16(ip.payload, 2) != 68) return false;

        const msg = dhcp_message.Message.parse(ip.payload[8..udp_len]) catch return false;
        if (msg.op != dhcp_message.op_reply) return true;
        const mac = msg.clientMac() orelse return false;
        var client_ptr: ?*DhcpClient = null;
        for (self.dhcp_clients.items) |*client| {
            if (client.port.eql(ingress) and client.mac.eql(mac)) {
                client_ptr = client;
                break;
            }
        }
        const client = client_ptr orelse return false;
        if (msg.xid != client.xid) return true;

        const typ = msg.messageType() orelse return true;
        switch (typ) {
            .offer => {
                if (client.state != .selecting) return true;
                const server = msg.options.serverId() orelse return true;
                if (msg.yiaddr.isUnspecified()) return true;
                client.server_ip = server;
                client.offered_ip = msg.yiaddr;
                client.subnet_mask = ipv4Option(msg.options.get(1));
                client.router = ipv4Option(msg.options.get(3));
                client.lease_seconds = u32Option(msg.options.get(51)) orelse 3600;
                client.renew_seconds = u32Option(msg.options.get(58)) orelse 0;
                client.rebind_seconds = u32Option(msg.options.get(59)) orelse 0;
                client.state = .requesting;
                client.attempts = 0;
                client.last_sent_ms = 0;
            },
            .ack => {
                switch (client.state) {
                    .requesting, .renewing, .rebinding => {},
                    else => return true,
                }
                const server = msg.options.serverId() orelse return true;
                if (client.state == .requesting) {
                    if (client.server_ip) |selected| {
                        if (!server.eql(selected)) return true;
                    }
                }
                // RENEWING/REBINDING requests carry no server identifier, so
                // any server that answers with an ACK is authoritative
                // (RFC 2131 section 4.4.5).
                client.server_ip = server;
                if (!msg.yiaddr.isUnspecified()) client.offered_ip = msg.yiaddr;
                const ip_addr = client.offered_ip orelse return true;
                if (ip_addr.isUnspecified()) return true;
                client.subnet_mask = ipv4Option(msg.options.get(1)) orelse client.subnet_mask;
                client.router = ipv4Option(msg.options.get(3)) orelse client.router;
                client.lease_seconds = u32Option(msg.options.get(51)) orelse client.lease_seconds;
                if (client.lease_seconds == 0) client.lease_seconds = 3600;
                if (u32Option(msg.options.get(58))) |renew| client.renew_seconds = renew;
                if (u32Option(msg.options.get(59))) |rebind| client.rebind_seconds = rebind;
                self.applyDhcpClient(client, now);
                client.state = .bound;
                client.attempts = 0;
                client.last_sent_ms = 0;
            },
            .nak => {
                switch (client.state) {
                    .requesting, .renewing, .rebinding => {},
                    else => return true,
                }
                _ = msg.options.serverId() orelse return true;
                self.clearDhcpClient(client);
                self.beginDhcpSelection(io, client);
            },
            else => {},
        }
        return true;
    }

    fn applyDhcpClient(self: *Forwarder, client: *DhcpClient, now: i64) void {
        const ip = client.offered_ip orelse return;
        const mask = client.subnet_mask orelse types.Ipv4{ .value = 0xffffff00 };
        const prefix_len = maskToPrefix(mask);
        const prefix = types.Prefix4{ .addr = ip, .len = prefix_len };
        const was_configured = client.configured;

        const prefix_changed = if (client.configured_prefix) |old|
            old.len != prefix.len or !old.addr.eql(prefix.addr)
        else
            true;
        const router_changed = if (client.configured_router) |old|
            if (client.router) |router| !old.eql(router) else true
        else
            client.router != null;

        if (prefix_changed) {
            if (client.configured_prefix) |old| {
                self.removeLocal(old, client.port, 0);
                _ = self.fib.remove(.{ .addr = old.network(), .len = old.len }, client.port);
            }
        }
        if (router_changed) {
            if (client.configured_router) |old| {
                self.removeDefaultRoute(client.port, old);
            }
        }

        if (!was_configured or prefix_changed) {
            self.addLocal(prefix, client.port, 0) catch {};
            self.addRoute(.{
                .prefix = .{ .addr = prefix.network(), .len = prefix.len },
                .port = client.port,
                .kind = .connected,
            }) catch {};
        }
        if (client.router) |router| {
            if (!was_configured or router_changed) {
                self.addRoute(.{
                    .prefix = .{ .addr = .{}, .len = 0 },
                    .next_hop = router,
                    .port = client.port,
                    .kind = .static,
                }) catch {};
            }
        }
        if (client.want_masquerade) {
            self.addSnatRule(client.port, ip) catch {};
        }

        client.configured = true;
        client.configured_prefix = prefix;
        client.configured_router = client.router;
        if (!was_configured) self.counters.dhcp_client_bound += 1;
        self.setDhcpTimers(client, now);
    }

    fn setDhcpTimers(self: *Forwarder, client: *DhcpClient, now: i64) void {
        _ = self;
        const lease_seconds: u32 = if (client.lease_seconds == 0) 3600 else client.lease_seconds;
        const lease_ms = @as(i64, @intCast(lease_seconds)) * 1000;
        var renew_ms = if (client.renew_seconds != 0)
            @as(i64, @intCast(client.renew_seconds)) * 1000
        else
            @divTrunc(lease_ms, 2);
        var rebind_ms = if (client.rebind_seconds != 0)
            @as(i64, @intCast(client.rebind_seconds)) * 1000
        else
            @divTrunc(lease_ms * 7, 8);
        if (renew_ms <= 0 or renew_ms >= lease_ms) renew_ms = @divTrunc(lease_ms, 2);
        if (rebind_ms <= renew_ms or rebind_ms >= lease_ms) rebind_ms = @divTrunc(lease_ms * 7, 8);

        client.renew_at_ms = now + renew_ms;
        client.rebind_at_ms = now + rebind_ms;
        client.lease_expires_ms = now + lease_ms;
    }

    fn sendDhcpClientMessage(
        self: *Forwarder,
        io: std.Io,
        client: *DhcpClient,
        typ: dhcp_message.MessageType,
        requested: ?types.Ipv4,
    ) PortError!void {
        const renewing = client.state == .renewing or client.state == .rebinding;
        var msg_buf: [512]u8 = undefined;
        var builder = dhcp_message.Builder.init(&msg_buf, dhcp_message.op_request, typ, client.xid, client.mac, 0x8000) catch
            return error.FrameTooLarge;
        if (renewing) {
            if (client.offered_ip) |current| builder.setCiaddr(current);
        } else {
            builder.addOption(55, &.{ 1, 3, 6, 51, 54, 58, 59 }) catch return error.FrameTooLarge;
        }
        if (requested) |ip| (builder.addIpv4(50, ip) catch return error.FrameTooLarge);
        if (!renewing) {
            if (client.server_ip) |server| {
                if (typ == .request) (builder.addIpv4(54, server) catch return error.FrameTooLarge);
            }
        }
        const payload = builder.finish() catch return error.FrameTooLarge;

        var udp: [576]u8 = undefined;
        const udp_len = 8 + payload.len;
        if (udp_len > udp.len) return error.FrameTooLarge;
        writeU16(&udp, 0, 68);
        writeU16(&udp, 2, 67);
        writeU16(&udp, 4, @intCast(udp_len));
        writeU16(&udp, 6, 0);
        @memcpy(udp[8..udp_len], payload);

        var ip_buf: [576]u8 = undefined;
        const src_ip = if (renewing) client.offered_ip orelse types.Ipv4.unspecified else types.Ipv4.unspecified;
        const dst_ip = types.Ipv4.limited_broadcast;
        const ip_len = ipv4.write(
            &ip_buf,
            src_ip,
            dst_ip,
            ipv4.Protocol.udp,
            64,
            0,
            udp[0..udp_len],
        ) catch return error.FrameTooLarge;

        const parsed = ipv4.parse(ip_buf[0..ip_len]) catch return error.InvalidArgument;
        const udp_mut = ip_buf[parsed.header_len..ip_len];
        var sum = transportChecksum(parsed.src, parsed.dst, ipv4.Protocol.udp, udp_mut);
        if (sum == 0) sum = 0xffff;
        writeU16(udp_mut, 6, sum);
        writeU16(&ip_buf, 10, 0);
        writeU16(&ip_buf, 10, ipv4.checksum(ip_buf[0..parsed.header_len]));

        try self.sendL2(
            io,
            client.port,
            types.Mac.broadcast,
            ethernet.EtherType.ipv4,
            ip_buf[0..ip_len],
        );
    }

    fn newDhcpXid(io: std.Io) u32 {
        var bytes: [4]u8 = undefined;
        io.random(&bytes);
        const xid = std.mem.readInt(u32, &bytes, .big);
        return if (xid == 0) 1 else xid;
    }

    fn maskToPrefix(mask: types.Ipv4) u8 {
        var count: u8 = 0;
        var value = mask.value;
        while (value & 0x80000000 != 0) {
            count += 1;
            value <<= 1;
        }
        return count;
    }

    fn ipv4Option(data: ?[]const u8) ?types.Ipv4 {
        const bytes = data orelse return null;
        if (bytes.len != 4) return null;
        return .{ .value = std.mem.readInt(u32, bytes[0..4], .big) };
    }

    fn u32Option(data: ?[]const u8) ?u32 {
        const bytes = data orelse return null;
        if (bytes.len != 4) return null;
        return std.mem.readInt(u32, bytes[0..4], .big);
    }

    fn handleIpv4(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
        vlan: u16,
    ) PortError!void {
        const total: usize = ip.total_len;
        const now = nowMs(io);
        if (try self.handleDhcpClient(io, ip, ingress, now)) return;
        if (try self.handleDhcp(io, ip, ingress, vlan, now)) return;
        if (try self.translateIcmpError(io, eth, ip, ingress, vlan, now)) return;
        const is_local = self.isLocal(ip.dst, vlan);
        const flow_key = flowKey(ip, self.trafficZone(ingress), vlan);

        var entry: ?*conntrack_mod.Entry = null;
        var direction: Direction = .new;
        if (flow_key) |key| {
            if (self.conntrack.lookup(key)) |found| {
                if (found.original.eql(key)) {
                    entry = found;
                    direction = .original;
                } else if (found.reply.eql(key)) {
                    entry = found;
                    direction = .reply;
                }
            }
        }

        var dnat_rule: ?nat_mod.ForwardRule = null;
        if (entry == null and is_local) {
            if (flow_key) |key| dnat_rule = self.dnatRuleFor(key, ingress);
        }

        // Replies to a NAT address and new port-forwarded flows are
        // destined to a local IP but must be translated and forwarded.
        if (is_local) {
            const forwardable = if (entry) |found| blk: {
                const nat_info = found.nat orelse break :blk false;
                if (direction == .reply) break :blk true;
                break :blk nat_info.dnat_addr != null;
            } else dnat_rule != null;
            if (!forwardable) {
                try self.handleLocal(io, eth, ip, ingress, vlan);
                return;
            }
        }

        if (!is_local and (ip.dst.isMulticast() or ip.dst.isUnspecified() or
            ip.dst.eql(types.Ipv4.limited_broadcast)))
        {
            self.counters.dropped += 1;
            return;
        }
        if (self.firewall.rp_filter and !self.sourceOnIngress(ip.src, ingress, vlan)) {
            self.counters.dropped += 1;
            self.counters.firewall_dropped += 1;
            self.counters.firewall_spoofed += 1;
            return;
        }
        if (ip.ttl <= 1) {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ip,
                ingress,
                icmp.Type.time_exceeded,
                icmp.Code.ttl_exceeded,
                0,
                vlan,
            );
            return;
        }

        var packet_buf: [2048]u8 = undefined;
        if (total > packet_buf.len) {
            self.counters.dropped += 1;
            return;
        }
        @memcpy(packet_buf[0..total], ip.packet[0..total]);
        const packet = packet_buf[0..total];
        var ipm = ipv4.parse(packet) catch {
            self.counters.dropped += 1;
            return;
        };

        if (entry) |found| {
            updateFlow(found, ipm, now, direction == .reply);
            if (direction == .reply) {
                if (found.nat) |nat_info| {
                    if (nat_info.snat_addr != null) {
                        if (!nat_mod.rewriteDestination(packet, found.original.src, found.original.sport)) {
                            self.counters.dropped += 1;
                            return;
                        }
                        ipm = ipv4.parse(packet) catch {
                            self.counters.dropped += 1;
                            return;
                        };
                    }
                    if (nat_info.dnat_addr != null) {
                        if (!nat_mod.rewriteSource(packet, found.original.dst, found.original.dport)) {
                            self.counters.dropped += 1;
                            return;
                        }
                        ipm = ipv4.parse(packet) catch {
                            self.counters.dropped += 1;
                            return;
                        };
                    }
                }
            } else if (found.nat) |nat_info| {
                if (nat_info.dnat_addr) |dnat_addr| {
                    if (!nat_mod.rewriteDestination(packet, dnat_addr, nat_info.dnat_port)) {
                        self.counters.dropped += 1;
                        return;
                    }
                    ipm = ipv4.parse(packet) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                    self.counters.dnat_packets += 1;
                }
            }
        } else if (dnat_rule) |rule| {
            if (!nat_mod.rewriteDestination(packet, rule.to_addr, rule.to_port)) {
                self.counters.dropped += 1;
                return;
            }
            ipm = ipv4.parse(packet) catch {
                self.counters.dropped += 1;
                return;
            };
            self.counters.dnat_packets += 1;
        }

        const route = self.fib.lookup(ipm.dst) orelse {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ipm,
                ingress,
                icmp.Type.destination_unreachable,
                icmp.Code.net_unreachable,
                0,
                vlan,
            );
            return;
        };

        // Ordered rules run before the default policy. Existing conntrack
        // entries are the stateful shortcut: when no rule matches they are
        // accepted even under a default-drop policy.
        const fw_state: schema.FirewallCtState = if (entry != null) .established else .new;
        if (self.firewallAction(ingress, route.port, ipm, fw_state)) |action| {
            switch (action) {
                .accept => {},
                .drop => {
                    self.counters.dropped += 1;
                    self.counters.firewall_dropped += 1;
                    return;
                },
                .reject => {
                    self.counters.dropped += 1;
                    self.counters.firewall_dropped += 1;
                    try self.sendError(
                        io,
                        eth,
                        ipm,
                        ingress,
                        icmp.Type.destination_unreachable,
                        icmp.Code.admin_prohibited,
                        0,
                        vlan,
                    );
                    return;
                },
            }
        } else if (entry == null and dnat_rule == null) {
            // An explicit port-forward rule is an administrator allow for the
            // flow it creates; only traffic with neither a conntrack entry nor
            // a DNAT rule is subject to the default forwarding policy.
            switch (self.firewall.default_forward) {
                .accept => {},
                .drop => {
                    self.counters.dropped += 1;
                    self.counters.firewall_dropped += 1;
                    return;
                },
                .reject => {
                    self.counters.dropped += 1;
                    self.counters.firewall_dropped += 1;
                    try self.sendError(
                        io,
                        eth,
                        ipm,
                        ingress,
                        icmp.Type.destination_unreachable,
                        icmp.Code.admin_prohibited,
                        0,
                        vlan,
                    );
                    return;
                },
            }
        }

        const egress = self.portById(route.port) orelse {
            self.counters.dropped += 1;
            return;
        };
        const egress_info = egress.port.info();
        // A bridge route's port is only its first member; the real egress
        // member (and therefore the correct MTU) is chosen after ARP.
        if (route.bridge == null and ipm.total_len > egress_info.mtu) {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ipm,
                ingress,
                icmp.Type.destination_unreachable,
                icmp.Code.frag_needed,
                egress_info.mtu,
                vlan,
            );
            return;
        }

        if (entry) |found| {
            if (direction == .original) {
                if (found.nat) |nat_info| {
                    if (nat_info.snat_addr) |snat_addr| {
                        if (!nat_mod.rewriteSource(packet, snat_addr, nat_info.snat_port)) {
                            self.counters.dropped += 1;
                            return;
                        }
                        ipm = ipv4.parse(packet) catch {
                            self.counters.dropped += 1;
                            return;
                        };
                        self.counters.snat_packets += 1;
                    }
                }
            }
        } else if (flow_key) |key| {
            if (dnat_rule) |rule| {
                var nat_info = conntrack_mod.Nat{
                    .dnat_addr = rule.to_addr,
                    .dnat_port = rule.to_port,
                };
                var reply_key: conntrack_mod.FlowKey = undefined;
                var translated_key: conntrack_mod.FlowKey = undefined;
                var hairpin_addr: ?types.Ipv4 = null;
                var hairpin_port: u16 = 0;
                if (route.port.eql(ingress) or self.sameBridge(route.port, ingress)) {
                    const local = self.localForPeer(route.port, ipm.dst, route.vlan) orelse {
                        self.counters.dropped += 1;
                        return;
                    };
                    const snat_port = self.conntrack.allocPort(ipm.protocol, local.prefix.addr, key.sport) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                    hairpin_addr = local.prefix.addr;
                    hairpin_port = snat_port;
                    nat_info.snat_addr = local.prefix.addr;
                    nat_info.snat_port = snat_port;
                    reply_key = makeHairpinReplyKey(
                        key,
                        rule.to_addr,
                        rule.to_port,
                        local.prefix.addr,
                        snat_port,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                    translated_key = makeTranslatedKey(
                        key,
                        local.prefix.addr,
                        snat_port,
                        rule.to_addr,
                        rule.to_port,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                } else {
                    reply_key = makeDnatReplyKey(
                        key,
                        rule.to_addr,
                        rule.to_port,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                    translated_key = makeTranslatedKey(
                        key,
                        key.src,
                        key.sport,
                        rule.to_addr,
                        rule.to_port,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                }

                const created = self.conntrack.createMapped(
                    key,
                    reply_key,
                    translated_key,
                    nat_info,
                    now,
                    initialTimeout(ipm.protocol),
                ) catch {
                    if (hairpin_addr) |addr| self.conntrack.freePort(ipm.protocol, addr, hairpin_port);
                    self.counters.dropped += 1;
                    return;
                };
                updateFlow(created, ipm, now, false);
                if (hairpin_addr) |addr| {
                    if (!nat_mod.rewriteSource(packet, addr, hairpin_port)) {
                        self.conntrack.remove(created);
                        self.counters.dropped += 1;
                        return;
                    }
                    ipm = ipv4.parse(packet) catch {
                        self.conntrack.remove(created);
                        self.counters.dropped += 1;
                        return;
                    };
                    self.counters.snat_packets += 1;
                }
            } else if (self.snatAddrFor(route.port)) |nat_addr| {
                if (ipm.src.eql(nat_addr)) {
                    const reply_key = makeReplyKey(
                        key,
                        key.src,
                        key.sport,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                    const created = self.conntrack.create(
                        key,
                        reply_key,
                        null,
                        now,
                        initialTimeout(ipm.protocol),
                    ) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                    updateFlow(created, ipm, now, false);
                } else {
                    const nat_port = self.conntrack.allocPort(ipm.protocol, nat_addr, key.sport) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                    const reply_key = makeReplyKey(
                        key,
                        nat_addr,
                        nat_port,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                    const translated_key = makeTranslatedKey(
                        key,
                        nat_addr,
                        nat_port,
                        key.dst,
                        key.dport,
                        self.trafficZone(route.port),
                        route.vlan,
                    );
                    const nat_info = conntrack_mod.Nat{
                        .snat_addr = nat_addr,
                        .snat_port = nat_port,
                    };
                    const created = self.conntrack.createMapped(
                        key,
                        reply_key,
                        translated_key,
                        nat_info,
                        now,
                        initialTimeout(ipm.protocol),
                    ) catch {
                        self.conntrack.freePort(ipm.protocol, nat_addr, nat_port);
                        self.counters.dropped += 1;
                        return;
                    };
                    updateFlow(created, ipm, now, false);
                    if (!nat_mod.rewriteSource(packet, nat_addr, nat_port)) {
                        self.conntrack.remove(created);
                        self.counters.dropped += 1;
                        return;
                    }
                    ipm = ipv4.parse(packet) catch {
                        self.conntrack.remove(created);
                        self.counters.dropped += 1;
                        return;
                    };
                    self.counters.snat_packets += 1;
                }
            } else {
                const reply_key = makeReplyKey(
                    key,
                    key.src,
                    key.sport,
                    self.trafficZone(route.port),
                    route.vlan,
                );
                const created = self.conntrack.create(
                    key,
                    reply_key,
                    null,
                    now,
                    initialTimeout(ipm.protocol),
                ) catch {
                    self.counters.dropped += 1;
                    return;
                };
                updateFlow(created, ipm, now, false);
            }
        } else if (self.snatAddrFor(route.port) != null) {
            self.counters.dropped += 1;
            self.counters.nat_unsupported += 1;
            return;
        }

        // TUN ports carry bare IP; ARP and Ethernet rewriting do not apply.
        if (egress_info.kind == .tun) {
            var out: [2048]u8 = undefined;
            if (total > out.len) {
                self.counters.dropped += 1;
                return;
            }
            @memcpy(out[0..total], ipm.packet[0..total]);
            ipv4.decrementTtl(out[0..total]) catch {
                self.counters.dropped += 1;
                return;
            };
            fixTransportChecksum(out[0..total]);
            try egress.port.write(io, out[0..total]);
            self.counters.forwarded += 1;
            return;
        }

        const next_hop = route.next_hop orelse ipm.dst;
        var arp_entry: ?arp.Entry = null;
        var egress_port = route.port;
        if (route.bridge) |bridge_id| {
            if (self.arp.getFreshAnyVlan(next_hop, route.vlan, now, arp_ttl_ms)) |found| {
                if (self.bridgeById(bridge_id)) |bridge| {
                    if (bridge.contains(found.port) and
                        egressVlan(bridge, found.port, route.vlan) != .filtered)
                    {
                        arp_entry = found;
                        egress_port = found.port;
                    }
                }
            }
            if (arp_entry == null) {
                try self.sendArpRequestBridge(io, bridge_id, next_hop, route.vlan);
                if (!self.enqueuePending(route.port, next_hop, route.vlan, ipm.packet[0..total], now)) {
                    self.counters.dropped += 1;
                    self.counters.pending_dropped += 1;
                }
                return;
            }
        } else {
            arp_entry = self.arp.getFreshVlan(next_hop, route.vlan, route.port, now, arp_ttl_ms);
            if (arp_entry == null) {
                try self.sendArpRequest(io, route.port, next_hop, route.vlan);
                if (!self.enqueuePending(route.port, next_hop, route.vlan, ipm.packet[0..total], now)) {
                    self.counters.dropped += 1;
                    self.counters.pending_dropped += 1;
                }
                return;
            }
        }
        const resolved = arp_entry.?;
        const final_egress = self.portById(egress_port) orelse {
            self.counters.dropped += 1;
            return;
        };
        const final_info = final_egress.port.info();
        if (ipm.total_len > final_info.mtu) {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ipm,
                ingress,
                icmp.Type.destination_unreachable,
                icmp.Code.frag_needed,
                final_info.mtu,
                vlan,
            );
            return;
        }

        var out: [2048]u8 = undefined;
        if (total > out.len) {
            self.counters.dropped += 1;
            return;
        }
        @memcpy(out[0..total], ipm.packet[0..total]);
        ipv4.decrementTtl(out[0..total]) catch {
            self.counters.dropped += 1;
            return;
        };
        fixTransportChecksum(out[0..total]);
        self.sendL2Vlan(io, egress_port, resolved.mac, ethernet.EtherType.ipv4, out[0..total], route.vlan) catch {
            self.counters.dropped += 1;
            return;
        };
        self.counters.forwarded += 1;
    }

    fn handleDhcp(
        self: *Forwarder,
        io: std.Io,
        ip: ipv4.Header,
        ingress: types.PortId,
        vlan: u16,
        now: i64,
    ) PortError!bool {
        if (ip.protocol != ipv4.Protocol.udp) return false;
        if (ip.payload.len < 8) return false;
        const udp_len = readU16(ip.payload, 4);
        if (udp_len < 8 or udp_len > ip.payload.len) return false;
        if (readU16(ip.payload, 2) != 67) return false;

        const server = self.dhcpServerFor(ingress, vlan) orelse return false;
        if (!self.dhcp_limiter.allow(now)) {
            self.counters.dhcp_rate_limited += 1;
            return true;
        }
        self.counters.dhcp_requests += 1;
        const msg = dhcp_message.Message.parse(ip.payload[8..udp_len]) catch {
            self.counters.dhcp_dropped += 1;
            return true;
        };

        const client_mac = msg.clientMac() orelse {
            self.counters.dhcp_dropped += 1;
            return true;
        };
        var reply_buf: [576]u8 = undefined;
        var reply: ?dhcp_server.Reply = null;
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            const candidate = (server.handle(msg, &reply_buf, now) catch {
                self.counters.dhcp_dropped += 1;
                return true;
            }) orelse return true;
            if (candidate.typ != .offer) {
                reply = candidate;
                break;
            }
            // Conflict detection: only trust ARP entries learned on the same
            // L2 segment; a host elsewhere in a routed network cannot own an
            // address from this pool.
            if (self.arp.getFreshAnyVlan(candidate.yiaddr, vlan, now, arp_ttl_ms)) |entry| {
                const same_segment = entry.port.eql(ingress) or self.sameBridge(entry.port, ingress);
                if (same_segment and !entry.mac.eql(client_mac)) {
                    server.decline(client_mac, candidate.yiaddr, now);
                    self.counters.dhcp_conflicts += 1;
                    continue;
                }
            }
            reply = candidate;
            break;
        }
        const final_reply = reply orelse return true;

        if (final_reply.typ == .offer) {
            if (!self.queueDhcpOffer(ingress, server.cfg.bridge, vlan, client_mac, final_reply, now)) {
                self.counters.dhcp_dropped += 1;
                return true;
            }
            self.probeDhcpOffer(io, server, final_reply.yiaddr, vlan);
            return true;
        }

        switch (final_reply.typ) {
            .ack => self.counters.dhcp_acks += 1,
            .nak => self.counters.dhcp_naks += 1,
            else => {},
        }
        self.sendDhcpReply(io, ingress, final_reply, vlan) catch {
            self.counters.dhcp_dropped += 1;
            return true;
        };
        return true;
    }

    fn queueDhcpOffer(
        self: *Forwarder,
        port: types.PortId,
        bridge: ?u32,
        vlan: u16,
        client_mac: types.Mac,
        reply: dhcp_server.Reply,
        now: i64,
    ) bool {
        if (reply.payload.len > dhcp_reply_max) return false;
        for (&self.dhcp_pending) |*slot| {
            if (slot.used) continue;
            @memcpy(slot.bytes[0..reply.payload.len], reply.payload);
            slot.used = true;
            slot.port = port;
            slot.bridge = bridge;
            slot.vlan = vlan;
            slot.client_mac = client_mac;
            slot.ip = reply.yiaddr;
            slot.queued_ms = now;
            slot.len = @intCast(reply.payload.len);
            slot.dst_ip = reply.dst_ip;
            slot.dst_mac = reply.dst_mac;
            return true;
        }
        return false;
    }

    fn probeDhcpOffer(self: *Forwarder, io: std.Io, server: *dhcp_server.Server, ip: types.Ipv4, vlan: u16) void {
        if (server.cfg.bridge) |bridge_id| {
            const bridge = self.bridgeById(bridge_id) orelse return;
            for (bridge.members) |member| {
                if (egressVlan(bridge, member, vlan) == .filtered) continue;
                self.sendArpProbe(io, member, ip, vlan) catch {};
            }
            return;
        }
        self.sendArpProbe(io, server.cfg.port, ip, vlan) catch {};
    }

    fn tickDhcpOffers(self: *Forwarder, io: std.Io, now: i64) void {
        for (&self.dhcp_pending) |*slot| {
            if (!slot.used) continue;
            if (now - slot.queued_ms < dhcp_probe_delay_ms) continue;

            const server = self.dhcpServerFor(slot.port, slot.vlan) orelse {
                slot.used = false;
                self.counters.dhcp_dropped += 1;
                continue;
            };
            if (self.arp.getFreshAnyVlan(slot.ip, slot.vlan, now, arp_ttl_ms)) |entry| {
                if (self.dhcpSameSegment(slot, entry.port) and !entry.mac.eql(slot.client_mac)) {
                    server.decline(slot.client_mac, slot.ip, now);
                    self.counters.dhcp_conflicts += 1;
                    slot.used = false;
                    continue;
                }
            }

            const reply = dhcp_server.Reply{
                .payload = slot.bytes[0..slot.len],
                .dst_ip = slot.dst_ip,
                .dst_mac = slot.dst_mac,
                .typ = .offer,
                .yiaddr = slot.ip,
            };
            self.sendDhcpReply(io, slot.port, reply, slot.vlan) catch {
                self.counters.dhcp_dropped += 1;
                slot.used = false;
                continue;
            };
            self.counters.dhcp_offers += 1;
            slot.used = false;
        }
    }

    fn dhcpSameSegment(self: *const Forwarder, slot: *const PendingDhcpOffer, port: types.PortId) bool {
        if (slot.bridge) |bridge_id| {
            if (self.bridgeById(bridge_id)) |bridge| {
                if (!bridge.contains(port)) return false;
                if (!bridge.vlan_aware) return true;
                const cfg = bridge.portVlan(port) orelse return false;
                if (cfg.pvid == slot.vlan) return true;
                return bridge.allowsTagged(port, slot.vlan);
            }
            return false;
        }
        return slot.port.eql(port);
    }

    fn dhcpServerFor(self: *Forwarder, ingress: types.PortId, vlan: u16) ?*dhcp_server.Server {
        for (self.dhcp_servers.items) |*server| {
            if (server.cfg.port.eql(ingress) and server.cfg.vlan == vlan) return server;
            if (server.cfg.bridge) |bridge_id| {
                if (server.cfg.vlan != vlan) continue;
                if (self.bridgeById(bridge_id)) |bridge| {
                    if (bridge.contains(ingress)) return server;
                }
            }
        }
        return null;
    }

    fn sendArpProbe(self: *Forwarder, io: std.Io, port: types.PortId, ip: types.Ipv4, vlan: u16) PortError!void {
        const port_mac = self.portMac(port);
        var arp_buf: [28]u8 = undefined;
        _ = arp.write(&arp_buf, .request, port_mac, .{ .value = 0 }, types.Mac{}, ip) catch return error.FrameTooLarge;
        try self.sendL2Vlan(io, port, types.Mac.broadcast, ethernet.EtherType.arp, &arp_buf, vlan);
    }

    fn sendDhcpReply(
        self: *Forwarder,
        io: std.Io,
        port: types.PortId,
        reply: dhcp_server.Reply,
        vlan: u16,
    ) PortError!void {
        var udp: [576]u8 = undefined;
        const udp_len = 8 + reply.payload.len;
        if (udp_len > udp.len) return error.FrameTooLarge;
        writeU16(&udp, 0, 67);
        writeU16(&udp, 2, 68);
        writeU16(&udp, 4, @intCast(udp_len));
        writeU16(&udp, 6, 0);
        @memcpy(udp[8..udp_len], reply.payload);

        var ip_buf: [576]u8 = undefined;
        const ip_len = ipv4.write(
            &ip_buf,
            self.dhcpServerAddress(port, vlan) orelse return error.NotFound,
            reply.dst_ip,
            ipv4.Protocol.udp,
            64,
            0,
            udp[0..udp_len],
        ) catch return error.FrameTooLarge;

        const parsed = ipv4.parse(ip_buf[0..ip_len]) catch return error.InvalidArgument;
        const udp_mut = ip_buf[parsed.header_len..ip_len];
        var sum = transportChecksum(parsed.src, parsed.dst, ipv4.Protocol.udp, udp_mut);
        if (sum == 0) sum = 0xffff;
        writeU16(udp_mut, 6, sum);
        writeU16(&ip_buf, 10, 0);
        writeU16(&ip_buf, 10, ipv4.checksum(ip_buf[0..parsed.header_len]));

        try self.sendL2Vlan(io, port, reply.dst_mac, ethernet.EtherType.ipv4, ip_buf[0..ip_len], vlan);
    }

    fn dhcpServerAddress(self: *const Forwarder, port: types.PortId, vlan: u16) ?types.Ipv4 {
        for (self.dhcp_servers.items) |server| {
            if (server.cfg.vlan != vlan) continue;
            if (server.cfg.port.eql(port)) return server.cfg.server_ip;
            if (server.cfg.bridge) |bridge_id| {
                if (self.bridgeById(bridge_id)) |bridge| {
                    if (bridge.contains(port)) return server.cfg.server_ip;
                }
            }
        }
        return null;
    }

    /// Rewrites ICMP errors quoting a translated NAT flow. Returns true when
    /// the packet was consumed (translated or dropped); false lets the normal
    /// forwarding/local path handle unrelated ICMP.
    fn translateIcmpError(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
        vlan: u16,
        now: i64,
    ) PortError!bool {
        if (ip.protocol != ipv4.Protocol.icmp) return false;
        const msg = ip.payload;
        if (msg.len < 8) return false;
        const typ = msg[0];
        if (typ != icmp.Type.destination_unreachable and
            typ != icmp.Type.time_exceeded and typ != 12)
        {
            return false;
        }
        if (ipv4.checksum(msg) != 0) {
            self.counters.dropped += 1;
            return true;
        }

        const quoted = msg[8..];
        const flow = parseQuoted(quoted) orelse {
            self.counters.dropped += 1;
            return true;
        };
        const translated_key = conntrack_mod.FlowKey{
            .zone = self.trafficZone(ingress),
            .proto = flow.proto,
            .src = flow.src,
            .sport = flow.sport,
            .dst = flow.dst,
            .dport = flow.dport,
            .vlan = vlan,
        };
        const found = self.conntrack.lookupTranslated(translated_key) orelse return false;
        const nat_info = found.nat orelse return false;

        if (nat_info.snat_addr) |snat| {
            if (!flow.src.eql(snat) or flow.sport != nat_info.snat_port) return false;
            if (!ip.dst.eql(snat)) return false;
        }
        if (nat_info.dnat_addr) |dnat| {
            if (!flow.dst.eql(dnat) or flow.dport != nat_info.dnat_port) return false;
        }
        if (ip.ttl <= 1) {
            self.counters.dropped += 1;
            return true;
        }

        var buf: [2048]u8 = undefined;
        const total: usize = ip.total_len;
        if (total > buf.len) {
            self.counters.dropped += 1;
            return true;
        }
        @memcpy(buf[0..total], ip.packet[0..total]);
        const outer = ipv4.parse(buf[0..total]) catch {
            self.counters.dropped += 1;
            return true;
        };
        const msg_mut = buf[outer.header_len..outer.total_len];
        const quoted_mut = msg_mut[8..];

        var new_src = outer.src;
        var new_dst = outer.dst;
        if (nat_info.snat_addr != null) new_dst = found.original.src;
        if (nat_info.dnat_addr != null) new_src = found.original.dst;
        std.mem.writeInt(u32, buf[12..16], new_src.value, .big);
        std.mem.writeInt(u32, buf[16..20], new_dst.value, .big);

        var emb_src = flow.src;
        var emb_dst = flow.dst;
        var emb_sport = flow.sport;
        var emb_dport = flow.dport;
        if (nat_info.snat_addr != null) {
            emb_src = found.original.src;
            emb_sport = found.original.sport;
        }
        if (nat_info.dnat_addr != null) {
            emb_dst = found.original.dst;
            emb_dport = found.original.dport;
        }
        std.mem.writeInt(u32, quoted_mut[12..16], emb_src.value, .big);
        std.mem.writeInt(u32, quoted_mut[16..20], emb_dst.value, .big);

        const l4 = quoted_mut[flow.header_len..];
        switch (flow.proto) {
            ipv4.Protocol.tcp => {
                writeU16(l4, 0, emb_sport);
                writeU16(l4, 2, emb_dport);
                if (l4.len >= 18) {
                    const old_sum = readU16(l4, 16);
                    if (old_sum != 0) {
                        var new_sum = nat_mod.adjustL4Checksum(
                            old_sum,
                            flow.src,
                            emb_src,
                            flow.dst,
                            emb_dst,
                            flow.sport,
                            emb_sport,
                            flow.dport,
                            emb_dport,
                        );
                        if (new_sum == 0) new_sum = 0xffff;
                        writeU16(l4, 16, new_sum);
                    }
                }
            },
            ipv4.Protocol.udp => {
                writeU16(l4, 0, emb_sport);
                writeU16(l4, 2, emb_dport);
                const old_sum = readU16(l4, 6);
                if (old_sum != 0) {
                    var new_sum = nat_mod.adjustL4Checksum(
                        old_sum,
                        flow.src,
                        emb_src,
                        flow.dst,
                        emb_dst,
                        flow.sport,
                        emb_sport,
                        flow.dport,
                        emb_dport,
                    );
                    if (new_sum == 0) new_sum = 0xffff;
                    writeU16(l4, 6, new_sum);
                }
            },
            ipv4.Protocol.icmp => {
                writeU16(l4, 4, emb_sport);
                const old_sum = readU16(l4, 2);
                writeU16(l4, 2, nat_mod.adjustWordChecksum(old_sum, flow.sport, emb_sport));
            },
            else => {},
        }

        writeU16(quoted_mut, 10, 0);
        writeU16(quoted_mut, 10, ipv4.checksum(quoted_mut[0..flow.header_len]));
        writeU16(msg_mut, 2, 0);
        writeU16(msg_mut, 2, ipv4.checksum(msg_mut));
        writeU16(&buf, 10, 0);
        writeU16(&buf, 10, ipv4.checksum(buf[0..outer.header_len]));

        const ipm = ipv4.parse(buf[0..total]) catch {
            self.counters.dropped += 1;
            return true;
        };
        const route = self.fib.lookup(ipm.dst) orelse {
            self.counters.dropped += 1;
            return true;
        };
        const egress = self.portById(route.port) orelse {
            self.counters.dropped += 1;
            return true;
        };
        const egress_info = egress.port.info();
        if (route.bridge == null and ipm.total_len > egress_info.mtu) {
            self.counters.dropped += 1;
            return true;
        }

        found.last_seen_ms = now;
        found.reply_packets += 1;
        found.reply_bytes += total;
        self.counters.icmp_translated += 1;

        if (egress_info.kind == .tun) {
            var out: [2048]u8 = undefined;
            @memcpy(out[0..total], ipm.packet[0..total]);
            ipv4.decrementTtl(out[0..total]) catch {
                self.counters.dropped += 1;
                return true;
            };
            fixTransportChecksum(out[0..total]);
            try egress.port.write(io, out[0..total]);
            self.counters.forwarded += 1;
            return true;
        }

        const next_hop = route.next_hop orelse ipm.dst;
        var arp_entry: ?arp.Entry = null;
        var egress_port = route.port;
        if (route.bridge) |bridge_id| {
            if (self.arp.getFreshAnyVlan(next_hop, route.vlan, now, arp_ttl_ms)) |found_arp| {
                if (self.bridgeById(bridge_id)) |bridge| {
                    if (bridge.contains(found_arp.port) and
                        egressVlan(bridge, found_arp.port, route.vlan) != .filtered)
                    {
                        arp_entry = found_arp;
                        egress_port = found_arp.port;
                    }
                }
            }
            if (arp_entry == null) {
                try self.sendArpRequestBridge(io, bridge_id, next_hop, route.vlan);
                if (!self.enqueuePending(route.port, next_hop, route.vlan, ipm.packet[0..total], now)) {
                    self.counters.dropped += 1;
                    self.counters.pending_dropped += 1;
                }
                return true;
            }
        } else {
            arp_entry = self.arp.getFreshVlan(next_hop, route.vlan, route.port, now, arp_ttl_ms);
            if (arp_entry == null) {
                try self.sendArpRequest(io, route.port, next_hop, route.vlan);
                if (!self.enqueuePending(route.port, next_hop, route.vlan, ipm.packet[0..total], now)) {
                    self.counters.dropped += 1;
                    self.counters.pending_dropped += 1;
                }
                return true;
            }
        }
        const resolved = arp_entry.?;
        const final_egress = self.portById(egress_port) orelse {
            self.counters.dropped += 1;
            return true;
        };
        const final_info = final_egress.port.info();
        if (ipm.total_len > final_info.mtu) {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ipm,
                ingress,
                icmp.Type.destination_unreachable,
                icmp.Code.frag_needed,
                final_info.mtu,
                vlan,
            );
            return true;
        }

        var out: [2048]u8 = undefined;
        if (total > out.len) {
            self.counters.dropped += 1;
            return true;
        }
        @memcpy(out[0..total], ipm.packet[0..total]);
        ipv4.decrementTtl(out[0..total]) catch {
            self.counters.dropped += 1;
            return true;
        };
        fixTransportChecksum(out[0..total]);
        self.sendL2Vlan(io, egress_port, resolved.mac, ethernet.EtherType.ipv4, out[0..total], route.vlan) catch {
            self.counters.dropped += 1;
            return true;
        };
        self.counters.forwarded += 1;
        return true;
    }

    fn handleLocal(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
        vlan: u16,
    ) PortError!void {
        if (ip.protocol != ipv4.Protocol.icmp or ip.payload.len < 8 or
            ip.payload[0] != icmp.Type.echo_request)
        {
            self.counters.dropped += 1;
            return;
        }

        const rule_action = self.firewallAction(ingress, null, ip, .new);
        const input_action = rule_action orelse self.firewall.default_in;
        switch (input_action) {
            .accept => {},
            .drop => {
                self.counters.dropped += 1;
                self.counters.firewall_dropped += 1;
                return;
            },
            .reject => {
                self.counters.dropped += 1;
                self.counters.firewall_dropped += 1;
                try self.sendError(
                    io,
                    eth,
                    ip,
                    ingress,
                    icmp.Type.destination_unreachable,
                    icmp.Code.admin_prohibited,
                    0,
                    vlan,
                );
                return;
            },
        }

        const entry = self.portById(ingress) orelse {
            self.counters.dropped += 1;
            return;
        };
        const info = entry.port.info();

        var msg_buf: [2048]u8 = undefined;
        const msg_len = icmp.writeEchoReply(&msg_buf, ip.payload) catch {
            self.counters.dropped += 1;
            return;
        };
        var ip_buf: [2048]u8 = undefined;
        const ip_len = ipv4.write(
            &ip_buf,
            ip.dst,
            ip.src,
            ipv4.Protocol.icmp,
            64,
            0,
            msg_buf[0..msg_len],
        ) catch {
            self.counters.dropped += 1;
            return;
        };

        if (info.kind == .tun) {
            try entry.port.write(io, ip_buf[0..ip_len]);
            self.counters.local_delivered += 1;
            return;
        }

        const l2 = eth orelse {
            self.counters.dropped += 1;
            return;
        };
        if (info.mac.isZero() or l2.src.isMulticast()) {
            self.counters.dropped += 1;
            return;
        }

        self.sendL2Vlan(
            io,
            ingress,
            l2.src,
            ethernet.EtherType.ipv4,
            ip_buf[0..ip_len],
            vlan,
        ) catch {
            self.counters.dropped += 1;
            return;
        };
        self.counters.local_delivered += 1;
    }

    fn sendError(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
        typ: u8,
        code: u8,
        rest: u32,
        vlan: u16,
    ) PortError!void {
        if (ip.fragmentOffset() != 0) return;
        if (ip.src.isUnspecified() or ip.src.isMulticast() or
            ip.src.eql(types.Ipv4.limited_broadcast)) return;
        if (ip.protocol == ipv4.Protocol.icmp and ip.payload.len >= 1) {
            const t = ip.payload[0];
            if (t != icmp.Type.echo_request and t != icmp.Type.echo_reply) return;
        }

        const local = self.localForPeer(ingress, ip.src, vlan) orelse return;
        const entry = self.portById(ingress) orelse return;
        const info = entry.port.info();
        if (!self.icmp_limiter.allow(nowMs(io))) {
            self.counters.icmp_rate_limited += 1;
            return;
        }

        var msg_buf: [576]u8 = undefined;
        const msg_len = icmp.writeError(&msg_buf, typ, code, ip.packet, rest) catch return;
        var ip_buf: [1024]u8 = undefined;
        const ip_len = ipv4.write(
            &ip_buf,
            local.prefix.addr,
            ip.src,
            ipv4.Protocol.icmp,
            64,
            0,
            msg_buf[0..msg_len],
        ) catch return;

        if (info.kind == .tun) {
            try entry.port.write(io, ip_buf[0..ip_len]);
            self.counters.icmp_errors += 1;
            return;
        }

        const l2 = eth orelse return;
        if (info.mac.isZero() or l2.src.isMulticast()) return;

        self.sendL2Vlan(io, ingress, l2.src, ethernet.EtherType.ipv4, ip_buf[0..ip_len], vlan) catch return;
        self.counters.icmp_errors += 1;
    }

    fn enqueuePending(
        self: *Forwarder,
        port: types.PortId,
        next_hop: types.Ipv4,
        vlan: u16,
        packet: []const u8,
        now: i64,
    ) bool {
        if (packet.len > pending_packet_max) return false;
        for (&self.pending) |*slot| {
            if (slot.used) continue;
            slot.* = .{
                .used = true,
                .port = port,
                .next_hop = next_hop,
                .vlan = vlan,
                .queued_ms = now,
                .len = @intCast(packet.len),
            };
            @memcpy(slot.bytes[0..packet.len], packet);
            self.counters.pending_queued += 1;
            return true;
        }
        return false;
    }

    fn gcPending(self: *Forwarder, now: i64) void {
        for (&self.pending) |*slot| {
            if (!slot.used) continue;
            if (now - slot.queued_ms < arp_pending_ttl_ms) continue;
            slot.used = false;
            self.counters.pending_dropped += 1;
        }
    }

    fn flushPending(
        self: *Forwarder,
        io: std.Io,
        port: types.PortId,
        next_hop: types.Ipv4,
        next_mac: types.Mac,
        vlan: u16,
    ) PortError!void {
        const entry = self.portById(port) orelse return;
        const info = entry.port.info();
        if (info.mac.isZero()) return;

        for (&self.pending) |*slot| {
            if (!slot.used or !slot.next_hop.eql(next_hop) or slot.vlan != vlan) continue;
            if (!slot.port.eql(port) and !self.sameBridge(slot.port, port)) continue;

            const len: usize = slot.len;
            slot.used = false;
            if (len > @as(usize, info.mtu)) {
                self.counters.pending_dropped += 1;
                continue;
            }
            var packet: [pending_packet_max]u8 = undefined;
            @memcpy(packet[0..len], slot.bytes[0..len]);

            ipv4.decrementTtl(packet[0..len]) catch {
                self.counters.pending_dropped += 1;
                continue;
            };
            fixTransportChecksum(packet[0..len]);
            self.sendL2Vlan(io, port, next_mac, ethernet.EtherType.ipv4, packet[0..len], vlan) catch {
                self.counters.pending_dropped += 1;
                continue;
            };
            self.counters.pending_flushed += 1;
            self.counters.forwarded += 1;
        }
    }

    fn sendArpRequest(
        self: *Forwarder,
        io: std.Io,
        egress: types.PortId,
        target: types.Ipv4,
        vlan: u16,
    ) PortError!void {
        try self.sendArpRequestLimited(io, egress, target, vlan, true);
    }

    fn sendArpRequestLimited(
        self: *Forwarder,
        io: std.Io,
        egress: types.PortId,
        target: types.Ipv4,
        vlan: u16,
        limit: bool,
    ) PortError!void {
        const entry = self.portById(egress) orelse return error.NotFound;
        const info = entry.port.info();
        if (info.kind == .tun or info.mac.isZero()) return;

        if (limit and !try self.recordArpMiss(io, target)) return;

        const local = self.localForPeer(egress, target, vlan) orelse return;
        var payload: [28]u8 = undefined;
        _ = arp.write(
            &payload,
            .request,
            info.mac,
            local.prefix.addr,
            types.Mac.zero,
            target,
        ) catch return;
        try self.sendL2Vlan(io, egress, types.Mac.broadcast, ethernet.EtherType.arp, &payload, vlan);
        self.counters.arp_requests += 1;
    }

    fn recordArpMiss(self: *Forwarder, io: std.Io, target: types.Ipv4) PortError!bool {
        const now = nowMs(io);
        if (self.arp_misses.get(target.value)) |last| {
            if (now - last < arp_request_interval_ms) return false;
        }
        if (self.arp_misses.count() >= arp_miss_max_entries) {
            self.arp_misses.clearRetainingCapacity();
        }
        try self.arp_misses.put(self.gpa, target.value, now);
        return true;
    }

    fn sendArpRequestBridge(self: *Forwarder, io: std.Io, bridge_id: u32, target: types.Ipv4, vlan: u16) PortError!void {
        const bridge = self.bridgeById(bridge_id) orelse return error.NotFound;
        // Rate-limit once for the whole bridge, then send on each member.
        // Otherwise an unresolved next hop generates one request per member
        // for every forwarded packet.
        if (!try self.recordArpMiss(io, target)) return;
        for (bridge.members) |member| {
            if (egressVlan(bridge, member, vlan) == .filtered) continue;
            self.sendArpRequestLimited(io, member, target, vlan, false) catch {};
        }
    }

    fn sameBridge(self: *const Forwarder, a: types.PortId, b: types.PortId) bool {
        const bridge = self.bridgeForPort(a) orelse return false;
        return bridge.contains(b);
    }

    fn sendL2(
        self: *Forwarder,
        io: std.Io,
        egress: types.PortId,
        dst: types.Mac,
        ethertype: u16,
        payload: []const u8,
    ) PortError!void {
        return self.sendL2Vlan(io, egress, dst, ethertype, payload, 0);
    }

    fn sendL2Vlan(
        self: *Forwarder,
        io: std.Io,
        egress: types.PortId,
        dst: types.Mac,
        ethertype: u16,
        payload: []const u8,
        vlan: u16,
    ) PortError!void {
        const entry = self.portById(egress) orelse return error.NotFound;
        const info = entry.port.info();
        if (info.mac.isZero()) return error.Unsupported;

        var tag: ?u16 = null;
        if (self.bridgeForPort(egress)) |bridge| {
            tag = switch (egressVlan(bridge, egress, vlan)) {
                .untagged => null,
                .tagged => |vid| vid,
                .filtered => return error.Unsupported,
            };
        } else if (vlan != 0) {
            return error.Unsupported;
        }

        var frame: [2048]u8 = undefined;
        const hlen = ethernet.write(&frame, dst, info.mac, ethertype, tag) catch
            return error.FrameTooLarge;
        if (payload.len > frame.len - hlen) return error.FrameTooLarge;
        if (payload.len > info.mtu) return error.FrameTooLarge;
        @memcpy(frame[hlen..][0..payload.len], payload);
        try entry.port.write(io, frame[0 .. hlen + payload.len]);
    }

    fn isLocal(self: *const Forwarder, ip: types.Ipv4, vlan: u16) bool {
        for (self.local.items) |local| {
            if (local.vlan == vlan and local.prefix.addr.value == ip.value) return true;
        }
        return false;
    }

    fn localOn(self: *const Forwarder, ip: types.Ipv4, port: types.PortId, vlan: u16) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port) and local.vlan == vlan and local.prefix.addr.value == ip.value) {
                return local;
            }
        }
        return null;
    }

    fn localForPort(self: *const Forwarder, port: types.PortId, vlan: u16) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port) and local.vlan == vlan) return local;
        }
        return null;
    }

    fn localForPeer(self: *const Forwarder, port: types.PortId, peer: types.Ipv4, vlan: u16) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port) and local.vlan == vlan and local.prefix.contains(peer)) return local;
        }
        return self.localForPort(port, vlan);
    }

    fn snatAddrFor(self: *const Forwarder, port: types.PortId) ?types.Ipv4 {
        for (self.snat_rules.items) |rule| {
            if (rule.port.eql(port)) return rule.addr;
        }
        return null;
    }

    fn dnatRuleFor(
        self: *const Forwarder,
        key: conntrack_mod.FlowKey,
        ingress: types.PortId,
    ) ?nat_mod.ForwardRule {
        for (self.forward_rules.items) |rule| {
            if (rule.proto != key.proto or rule.ext_port != key.dport) continue;
            if (rule.ingress) |required| {
                if (!required.eql(ingress)) continue;
            }
            return rule;
        }
        return null;
    }

    pub fn firewallRuleCount(self: *const Forwarder) usize {
        return self.firewall_rules.items.len;
    }

    /// Copies per-rule packet counters in rule order and returns the count.
    pub fn snapshotFirewallPackets(self: *const Forwarder, out: []u64) usize {
        const count = @min(out.len, self.firewall_rules.items.len);
        for (self.firewall_rules.items[0..count], 0..) |rule, i| out[i] = rule.packets;
        return count;
    }

    fn compileFirewall(self: *Forwarder, cfg: *const schema.Config) PortError!void {
        for (cfg.firewall.rules) |rule| {
            var compiled = FirewallRule{
                .action = rule.action,
                .proto = if (rule.proto) |proto| switch (proto) {
                    .tcp => ipv4.Protocol.tcp,
                    .udp => ipv4.Protocol.udp,
                    .icmp => ipv4.Protocol.icmp,
                } else null,
                .src = if (rule.src) |src| types.Prefix4.parse(src) catch
                    return error.InvalidArgument else null,
                .dst = if (rule.dst) |dst| types.Prefix4.parse(dst) catch
                    return error.InvalidArgument else null,
                .sport = rule.sport,
                .dport = rule.dport,
            };
            if (rule.iif) |name| {
                compiled.iif = self.firewallIface(cfg, name) orelse return error.NotFound;
            }
            if (rule.oif) |name| {
                compiled.oif = self.firewallIface(cfg, name) orelse return error.NotFound;
            }
            for (rule.ct_state) |state| {
                compiled.ct_mask |= firewallCtBit(state);
            }
            try self.firewall_rules.append(self.gpa, compiled);
        }
    }

    fn firewallIface(self: *const Forwarder, cfg: *const schema.Config, name: []const u8) ?FirewallIface {
        if (findPort(self.ports, name)) |entry| return .{ .port = entry.id };
        const itf = cfg.interfaces.get(name) orelse return null;
        if (itf.port) |port_name| {
            const entry = findPort(self.ports, port_name) orelse return null;
            return .{ .port = entry.id };
        }
        if (itf.bridge) |bridge_name| {
            const bridge = self.bridgeByName(cfg, bridge_name) orelse return null;
            return .{ .bridge = bridge.id };
        }
        return null;
    }

    const FirewallMatch = struct {
        index: usize,
        action: schema.FirewallAction,
    };

    fn firewallAction(
        self: *Forwarder,
        iif: types.PortId,
        oif: ?types.PortId,
        ip: ipv4.Header,
        state: schema.FirewallCtState,
    ) ?schema.FirewallAction {
        const matched = self.firewallMatch(iif, oif, ip, state) orelse return null;
        return matched.action;
    }

    fn firewallMatch(
        self: *Forwarder,
        iif: types.PortId,
        oif: ?types.PortId,
        ip: ipv4.Header,
        state: schema.FirewallCtState,
    ) ?FirewallMatch {
        const ports = firewallPorts(ip);
        for (self.firewall_rules.items, 0..) |*rule, index| {
            if (rule.proto) |proto| {
                if (proto != ip.protocol) continue;
            }
            if (rule.src) |prefix| {
                if (!prefix.contains(ip.src)) continue;
            }
            if (rule.dst) |prefix| {
                if (!prefix.contains(ip.dst)) continue;
            }
            if (rule.sport) |port| {
                if (ports.sport != port) continue;
            }
            if (rule.dport) |port| {
                if (ports.dport != port) continue;
            }
            if (rule.iif) |match| {
                if (!self.firewallIfaceMatches(match, iif)) continue;
            }
            if (rule.oif) |match| {
                const port = oif orelse continue;
                if (!self.firewallIfaceMatches(match, port)) continue;
            }
            if (rule.ct_mask != 0 and rule.ct_mask & firewallCtBit(state) == 0) continue;
            rule.packets += 1;
            return .{ .index = index, .action = rule.action };
        }
        return null;
    }

    fn firewallIfaceMatches(self: *const Forwarder, match: FirewallIface, port: types.PortId) bool {
        return switch (match) {
            .port => |required| required.eql(port),
            .bridge => |bridge_id| blk: {
                const bridge = self.bridgeForPort(port) orelse break :blk false;
                break :blk bridge.id == bridge_id;
            },
        };
    }

    fn bridgeByName(self: *const Forwarder, cfg: *const schema.Config, name: []const u8) ?Bridge {
        var it = cfg.bridges.iterator();
        var index: usize = 0;
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, name)) {
                if (index >= self.bridges.items.len) return null;
                return self.bridges.items[index];
            }
            index += 1;
        }
        return null;
    }

    fn bridgeById(self: *const Forwarder, id: u32) ?Bridge {
        for (self.bridges.items) |bridge| {
            if (bridge.id == id) return bridge;
        }
        return null;
    }

    fn bridgeForPort(self: *const Forwarder, port: types.PortId) ?Bridge {
        for (self.bridges.items) |bridge| {
            if (bridge.contains(port)) return bridge;
        }
        return null;
    }

    fn sourceOnIngress(
        self: *const Forwarder,
        src: types.Ipv4,
        ingress: types.PortId,
        vlan: u16,
    ) bool {
        if (src.isUnspecified() or src.isMulticast() or src.eql(types.Ipv4.limited_broadcast)) {
            return false;
        }
        const route = self.fib.lookup(src) orelse return false;
        if (route.vlan != vlan) return false;
        return route.port.eql(ingress) or self.sameBridge(route.port, ingress);
    }

    fn trafficZone(self: *const Forwarder, port: types.PortId) u32 {
        if (self.bridgeForPort(port)) |bridge| return 0x8000_0000 | bridge.id;
        return port.value;
    }

    fn portById(self: *const Forwarder, id: types.PortId) ?PortEntry {
        for (self.ports) |entry| {
            if (entry.id.eql(id)) return entry;
        }
        return null;
    }
};

/// AF_PACKET sees locally generated packets before some NICs complete checksum
/// offload; recomputing TCP/UDP checksums keeps forwarded traffic valid. The
/// cost is bounded to one pass over L4 and is revisited when offload is
/// negotiated (R3 perf).
fn fixTransportChecksum(packet: []u8) void {
    const header = ipv4.parse(packet) catch return;
    if (header.isFragment()) return;

    const payload = packet[header.header_len..header.total_len];
    switch (header.protocol) {
        ipv4.Protocol.tcp => {
            if (payload.len < 20) return;
            writeU16(payload, 16, 0);
            writeU16(payload, 16, transportChecksum(header.src, header.dst, header.protocol, payload));
        },
        ipv4.Protocol.udp => {
            if (payload.len < 8) return;
            const udp_len = readU16(payload, 4);
            if (udp_len < 8 or udp_len > payload.len) return;
            if (readU16(payload, 6) == 0) return;
            writeU16(payload, 6, 0);
            var sum = transportChecksum(header.src, header.dst, header.protocol, payload[0..udp_len]);
            if (sum == 0) sum = 0xffff;
            writeU16(payload, 6, sum);
        },
        else => {},
    }
}

fn transportChecksum(src: types.Ipv4, dst: types.Ipv4, protocol: u8, data: []const u8) u16 {
    var sum: u32 = 0;
    sum += (src.value >> 16) & 0xffff;
    sum += src.value & 0xffff;
    sum += (dst.value >> 16) & 0xffff;
    sum += dst.value & 0xffff;
    sum += protocol;
    sum += @intCast(data.len);

    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += readU16(data, i);
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @truncate(~sum);
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @truncate(value >> 8);
    buf[off + 1] = @truncate(value);
}

const Direction = enum { new, original, reply };

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn flowKey(ip: ipv4.Header, zone: u32, vlan: u16) ?conntrack_mod.FlowKey {
    if (ip.isFragment()) return null;
    if (ip.protocol == ipv4.Protocol.tcp) {
        if (ip.payload.len < 20) return null;
        return .{
            .zone = zone,
            .proto = ip.protocol,
            .src = ip.src,
            .sport = readU16(ip.payload, 0),
            .dst = ip.dst,
            .dport = readU16(ip.payload, 2),
            .vlan = vlan,
        };
    }
    if (ip.protocol == ipv4.Protocol.udp) {
        if (ip.payload.len < 8) return null;
        return .{
            .zone = zone,
            .proto = ip.protocol,
            .src = ip.src,
            .sport = readU16(ip.payload, 0),
            .dst = ip.dst,
            .dport = readU16(ip.payload, 2),
            .vlan = vlan,
        };
    }
    if (ip.protocol == ipv4.Protocol.icmp) {
        if (ip.payload.len < 8) return null;
        if (ip.payload[0] != icmp.Type.echo_request and ip.payload[0] != icmp.Type.echo_reply) {
            return null;
        }
        return .{
            .zone = zone,
            .proto = ip.protocol,
            .src = ip.src,
            .sport = readU16(ip.payload, 4),
            .dst = ip.dst,
            .dport = 0,
            .vlan = vlan,
        };
    }
    return null;
}

fn makeReplyKey(
    original: conntrack_mod.FlowKey,
    nat_addr: types.Ipv4,
    nat_port: u16,
    reply_zone: u32,
    reply_vlan: u16,
) conntrack_mod.FlowKey {
    if (original.proto == ipv4.Protocol.icmp) {
        return .{
            .zone = reply_zone,
            .proto = original.proto,
            .src = original.dst,
            .sport = nat_port,
            .dst = nat_addr,
            .dport = 0,
            .vlan = reply_vlan,
        };
    }
    return .{
        .zone = reply_zone,
        .proto = original.proto,
        .src = original.dst,
        .sport = original.dport,
        .dst = nat_addr,
        .dport = nat_port,
        .vlan = reply_vlan,
    };
}

const QuotedFlow = struct {
    header_len: usize,
    proto: u8,
    src: types.Ipv4,
    sport: u16,
    dst: types.Ipv4,
    dport: u16,
};

fn parseQuoted(quoted: []const u8) ?QuotedFlow {
    if (quoted.len < 20) return null;
    if (quoted[0] >> 4 != 4) return null;
    const ihl = quoted[0] & 0x0f;
    if (ihl < 5) return null;
    const header_len: usize = @as(usize, ihl) * 4;
    if (quoted.len < header_len + 8) return null;
    if (ipv4.checksum(quoted[0..header_len]) != 0) return null;
    const total_len = readU16(quoted, 2);
    if (total_len < header_len + 8) return null;
    if (readU16(quoted, 6) & 0x3fff != 0) return null;

    const proto = quoted[9];
    const src: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted[12..16], .big) };
    const dst: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted[16..20], .big) };
    const l4 = quoted[header_len..];
    switch (proto) {
        ipv4.Protocol.tcp, ipv4.Protocol.udp => return .{
            .header_len = header_len,
            .proto = proto,
            .src = src,
            .sport = readU16(l4, 0),
            .dst = dst,
            .dport = readU16(l4, 2),
        },
        ipv4.Protocol.icmp => {
            if (l4[0] != icmp.Type.echo_request and l4[0] != icmp.Type.echo_reply) return null;
            return .{
                .header_len = header_len,
                .proto = proto,
                .src = src,
                .sport = readU16(l4, 4),
                .dst = dst,
                .dport = 0,
            };
        },
        else => return null,
    }
}

fn makeTranslatedKey(
    original: conntrack_mod.FlowKey,
    src: types.Ipv4,
    sport: u16,
    dst: types.Ipv4,
    dport: u16,
    zone: u32,
    vlan: u16,
) conntrack_mod.FlowKey {
    return .{
        .zone = zone,
        .proto = original.proto,
        .src = src,
        .sport = sport,
        .dst = dst,
        .dport = dport,
        .vlan = vlan,
    };
}

fn makeDnatReplyKey(
    original: conntrack_mod.FlowKey,
    target_addr: types.Ipv4,
    target_port: u16,
    reply_zone: u32,
    reply_vlan: u16,
) conntrack_mod.FlowKey {
    return .{
        .zone = reply_zone,
        .proto = original.proto,
        .src = target_addr,
        .sport = target_port,
        .dst = original.src,
        .dport = original.sport,
        .vlan = reply_vlan,
    };
}

fn makeHairpinReplyKey(
    original: conntrack_mod.FlowKey,
    target_addr: types.Ipv4,
    target_port: u16,
    snat_addr: types.Ipv4,
    snat_port: u16,
    reply_zone: u32,
    reply_vlan: u16,
) conntrack_mod.FlowKey {
    return .{
        .zone = reply_zone,
        .proto = original.proto,
        .src = target_addr,
        .sport = target_port,
        .dst = snat_addr,
        .dport = snat_port,
        .vlan = reply_vlan,
    };
}

fn firewallCtBit(state: schema.FirewallCtState) u8 {
    return switch (state) {
        .new => 1,
        .established => 2,
        .related => 4,
        .invalid => 8,
    };
}

const FirewallPorts = struct { sport: ?u16 = null, dport: ?u16 = null };

fn firewallPorts(ip: ipv4.Header) FirewallPorts {
    if (ip.protocol != ipv4.Protocol.tcp and ip.protocol != ipv4.Protocol.udp) return .{};
    // Non-initial fragments have no transport header to inspect.
    if (ip.fragmentOffset() != 0 or ip.payload.len < 4) return .{};
    return .{
        .sport = readU16(ip.payload, 0),
        .dport = readU16(ip.payload, 2),
    };
}

fn fdbKey(bridge_id: u32, vlan: u16, mac: types.Mac) u128 {
    var value: u64 = 0;
    for (mac.bytes) |byte| value = (value << 8) | byte;
    return (@as(u128, bridge_id) << 60) |
        (@as(u128, vlan) << 48) |
        @as(u128, value);
}

fn initialTimeout(proto: u8) i64 {
    return if (proto == ipv4.Protocol.tcp)
        conntrack_mod.tcp_syn_ms
    else
        conntrack_mod.timeoutFor(proto, .established);
}

fn tcpFlags(ip: ipv4.Header) ?u8 {
    if (ip.protocol != ipv4.Protocol.tcp or ip.payload.len < 20) return null;
    return ip.payload[13];
}

fn updateFlow(
    entry: *conntrack_mod.Entry,
    ip: ipv4.Header,
    now_ms: i64,
    is_reply: bool,
) void {
    if (is_reply) {
        entry.reply_packets += 1;
        entry.reply_bytes += ip.total_len;
    } else {
        entry.packets += 1;
        entry.bytes += ip.total_len;
    }

    if (entry.original.proto == ipv4.Protocol.tcp) {
        const flags = tcpFlags(ip) orelse 0;
        if (flags & TCP_RST != 0) {
            entry.state = .closing;
            entry.timeout_ms = conntrack_mod.tcp_rst_ms;
        } else if (flags & TCP_FIN != 0) {
            entry.state = .closing;
            entry.timeout_ms = conntrack_mod.tcp_fin_ms;
        } else if (flags & TCP_SYN != 0 and flags & TCP_ACK == 0) {
            entry.state = .new;
            entry.timeout_ms = conntrack_mod.tcp_syn_ms;
        } else {
            entry.state = .established;
            entry.timeout_ms = conntrack_mod.tcp_established_ms;
        }
    } else {
        entry.timeout_ms = conntrack_mod.timeoutFor(entry.original.proto, entry.state);
    }
    entry.last_seen_ms = now_ms;
}

fn resolveMasquerade(
    cfg: *const schema.Config,
    locals: []const LocalAddr,
    ports: []const PortEntry,
    out: []const u8,
) ?nat_mod.Rule {
    if (cfg.interfaces.get(out)) |itf| {
        const port_name = if (itf.port) |name|
            name
        else if (itf.bridge) |bridge_name| blk: {
            const bridge = cfg.bridges.get(bridge_name) orelse return null;
            if (bridge.offload == .kernel) break :blk bridge_name;
            if (bridge.ports.len == 0) return null;
            break :blk bridge.ports[0];
        } else return null;
        const port_entry = findPort(ports, port_name) orelse return null;
        const address = itf.address orelse return null;
        if (std.mem.eql(u8, address, "dhcp")) return null;
        const prefix = types.Prefix4.parse(address) catch return null;
        return .{ .port = port_entry.id, .addr = prefix.addr };
    }

    const port_entry = findPort(ports, out) orelse return null;
    for (locals) |local| {
        if (local.port.eql(port_entry.id)) return .{ .port = port_entry.id, .addr = local.prefix.addr };
    }
    return null;
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.now(.awake, io).toMilliseconds();
}

fn offloadTrunkVlans(
    gpa: std.mem.Allocator,
    cfg: *const schema.Config,
    bridge_name: []const u8,
    bridge: schema.BridgeConfig,
) ![]u16 {
    var seen: [4096]bool = @splat(false);
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
    var it = cfg.interfaces.iterator();
    while (it.next()) |entry| {
        const itf = entry.value_ptr.*;
        if (itf.bridge) |name| {
            if (std.mem.eql(u8, name, bridge_name)) {
                const vlan = itf.vlan orelse 1;
                if (vlan >= seen.len) return error.InvalidArgument;
                seen[vlan] = true;
            }
        }
    }

    var out: std.ArrayListUnmanaged(u16) = .empty;
    errdefer out.deinit(gpa);
    for (seen, 0..) |present, vid| {
        if (present and vid != 0 and vid != 1) try out.append(gpa, @intCast(vid));
    }
    return out.toOwnedSlice(gpa);
}

fn findPort(ports: []const PortEntry, name: []const u8) ?PortEntry {
    for (ports) |entry| {
        if (std.mem.eql(u8, entry.config_name, name)) return entry;
    }
    return null;
}

fn findRoutePort(cfg: *const schema.Config, ports: []const PortEntry, dev: []const u8) ?PortEntry {
    if (findPort(ports, dev)) |entry| return entry;
    const itf = cfg.interfaces.get(dev) orelse return null;
    const port_name = itf.port orelse return null;
    return findPort(ports, port_name);
}

const testing = std.testing;
const config_parse = @import("../config/parse.zig");

const port_a: types.PortId = .{ .value = 1 };
const port_b: types.PortId = .{ .value = 2 };
const port_tun: types.PortId = .{ .value = 3 };

const port_a_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0a } };
const port_b_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0b } };
const host_a_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x02 } };
const host_b_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x03 } };

fn writeStpTestFrame(
    buf: []u8,
    root: u64,
    cost: u32,
    port_id: u16,
) !usize {
    var payload: [stp.payload_len]u8 = undefined;
    _ = try stp.write(&payload, .{
        .root_id = root,
        .root_cost = cost,
        .bridge_id = root,
        .port_id = port_id,
    });
    const hlen = try ethernet.write(
        buf,
        stp.multicast,
        host_a_mac,
        @intCast(stp.payload_len),
        null,
    );
    @memcpy(buf[hlen..][0..stp.payload_len], &payload);
    return hlen + stp.payload_len;
}

fn testIp(comptime s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

fn testPrefix(comptime s: []const u8) types.Prefix4 {
    return types.Prefix4.parse(s) catch unreachable;
}

fn testNet(comptime s: []const u8) types.Prefix4 {
    const p = testPrefix(s);
    return .{ .addr = p.network(), .len = p.len };
}

fn setup(
    a: *@import("../port/memory.zig").MemoryPort,
    b: *@import("../port/memory.zig").MemoryPort,
    entries: *[2]PortEntry,
    fwd: *Forwarder,
) !void {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    a.* = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    a.mac = port_a_mac;
    b.* = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    b.mac = port_b_mac;

    entries.* = .{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    fwd.* = try Forwarder.init(testing.allocator, entries);
    try fwd.addLocal(testPrefix("10.0.1.1/24"), port_a, 0);
    try fwd.addLocal(testPrefix("10.0.2.1/24"), port_b, 0);
    try fwd.addRoute(.{ .prefix = testNet("10.0.1.0/24"), .port = port_a, .kind = .connected });
    try fwd.addRoute(.{ .prefix = testNet("10.0.2.0/24"), .port = port_b, .kind = .connected });
}

fn flushDhcpOffers(fwd: *Forwarder) void {
    for (&fwd.dhcp_pending) |*slot| {
        if (slot.used) slot.queued_ms = 0;
    }
    fwd.tick(testing.io);
}

fn takeIpv4Sent(port: anytype, out: []u8) !usize {
    while (try port.takeSent(out)) |n| {
        const h = try ethernet.parse(out[0..n]);
        if (h.ethertype == ethernet.EtherType.ipv4) return n;
    }
    return error.TestUnexpectedResult;
}

fn buildEchoRequest(
    buf: []u8,
    eth_dst: types.Mac,
    eth_src: types.Mac,
    src: types.Ipv4,
    dst: types.Ipv4,
    ttl: u8,
    payload: []const u8,
) !usize {
    var icmp_buf: [1024]u8 = undefined;
    const icmp_len = try icmp.writeEchoRequest(&icmp_buf, 0x1234, 1, payload);

    var ip_buf: [1200]u8 = undefined;
    const ip_len = try ipv4.write(
        &ip_buf,
        src,
        dst,
        ipv4.Protocol.icmp,
        ttl,
        0x1111,
        icmp_buf[0..icmp_len],
    );

    const hlen = try ethernet.write(buf, eth_dst, eth_src, ethernet.EtherType.ipv4, null);
    @memcpy(buf[hlen..][0..ip_len], ip_buf[0..ip_len]);
    return hlen + ip_len;
}

fn buildIpEcho(
    buf: []u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    ttl: u8,
    payload: []const u8,
) !usize {
    var icmp_buf: [1024]u8 = undefined;
    const icmp_len = try icmp.writeEchoRequest(&icmp_buf, 0x2222, 1, payload);
    return ipv4.write(buf, src, dst, ipv4.Protocol.icmp, ttl, 0x3333, icmp_buf[0..icmp_len]);
}

fn setupTun(
    t: *@import("../port/memory.zig").MemoryPort,
    a: *@import("../port/memory.zig").MemoryPort,
    entries: *[2]PortEntry,
    fwd: *Forwarder,
) !void {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    a.* = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    a.mac = port_a_mac;
    t.* = MemoryPort.init(testing.allocator, port_tun, "tun0", 1500);
    t.kind = .tun;

    entries.* = .{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_tun, .config_name = "tun0", .port = t.port() },
    };
    fwd.* = try Forwarder.init(testing.allocator, entries);
    try fwd.addLocal(testPrefix("10.0.1.1/24"), port_a, 0);
    try fwd.addLocal(testPrefix("10.0.3.1/24"), port_tun, 0);
    try fwd.addRoute(.{ .prefix = testNet("10.0.1.0/24"), .port = port_a, .kind = .connected });
    try fwd.addRoute(.{ .prefix = testNet("10.0.3.0/24"), .port = port_tun, .kind = .connected });
    try fwd.addRoute(.{
        .prefix = testNet("10.0.2.0/24"),
        .next_hop = testIp("10.0.1.2"),
        .port = port_a,
        .kind = .static,
    });
}

fn buildArpReply(
    buf: []u8,
    sender_mac: types.Mac,
    sender_ip: types.Ipv4,
    target_mac: types.Mac,
    target_ip: types.Ipv4,
) !usize {
    var payload: [28]u8 = undefined;
    _ = try arp.write(
        &payload,
        .reply,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    );
    const hlen = try ethernet.write(
        buf,
        target_mac,
        sender_mac,
        ethernet.EtherType.arp,
        null,
    );
    @memcpy(buf[hlen..][0..28], &payload);
    return hlen + 28;
}

fn buildArpRequest(
    buf: []u8,
    sender_mac: types.Mac,
    sender_ip: types.Ipv4,
    target_ip: types.Ipv4,
) !usize {
    var payload: [28]u8 = undefined;
    _ = try arp.write(
        &payload,
        .request,
        sender_mac,
        sender_ip,
        types.Mac.zero,
        target_ip,
    );
    const hlen = try ethernet.write(
        buf,
        types.Mac.broadcast,
        sender_mac,
        ethernet.EtherType.arp,
        null,
    );
    @memcpy(buf[hlen..][0..28], &payload);
    return hlen + 28;
}

test "firewall default policies drop and reject new flows" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        port_b_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        1234,
        53,
        64,
        "query",
    );

    fwd.firewall.default_forward = .drop;
    try fwd.handle(testing.io, frame[0..n], port_a);
    try testing.expectEqual(@as(?usize, null), try b.takeSent(&frame));
    try testing.expectEqual(@as(u64, 1), fwd.counters.firewall_dropped);

    fwd.firewall.default_forward = .reject;
    try fwd.handle(testing.io, frame[0..n], port_a);
    const rn = (try a.takeSent(&frame)).?;
    const ip_h = try ipv4.parse(frame[14..rn]);
    try testing.expectEqual(@as(u8, icmp.Type.destination_unreachable), ip_h.payload[0]);
    try testing.expectEqual(@as(u8, icmp.Code.admin_prohibited), ip_h.payload[1]);
    try testing.expectEqual(@as(u64, 2), fwd.counters.firewall_dropped);
}

test "forwarder routes ipv4 between connected ports" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "ping",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_b_mac));
    try testing.expect(eth.src.eql(port_b_mac));
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);

    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqualSlices(u8, "ping", ip_h.payload[8..]);
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.packet[0..ip_h.header_len]));
    try testing.expectEqual(@as(u64, 1), fwd.counters.forwarded);
}

test "forwarder answers arp for a local address" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var frame: [64]u8 = undefined;
    const n = try buildArpRequest(&frame, host_a_mac, testIp("10.0.1.2"), testIp("10.0.1.1"));
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [64]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_a_mac));
    try testing.expect(eth.src.eql(port_a_mac));
    try testing.expectEqual(ethernet.EtherType.arp, eth.ethertype);

    const reply = try arp.parse(eth.payload);
    try testing.expectEqual(arp.Operation.reply, reply.operation);
    try testing.expect(reply.sender_mac.eql(port_a_mac));
    try testing.expect(reply.sender_ip.eql(testIp("10.0.1.1")));
    try testing.expect(reply.target_ip.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u64, 1), fwd.counters.arp_replies);
}

test "forwarder replies to local echo requests" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.1.1"),
        64,
        "hello",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(icmp.Type.echo_reply, ip_h.payload[0]);
    try testing.expectEqualSlices(u8, "hello", ip_h.payload[8..]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.local_delivered);
}

test "forwarder emits ttl exceeded" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        1,
        "ttl",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);
    try testing.expectEqual(@as(usize, 0), b.queuedTx());

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(icmp.Type.time_exceeded, ip_h.payload[0]);
    try testing.expectEqual(icmp.Code.ttl_exceeded, ip_h.payload[1]);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_errors);
}

test "forwarder emits unreachable and arp request on miss" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("8.8.8.8"),
        64,
        "x",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(icmp.Type.destination_unreachable, ip_h.payload[0]);
    try testing.expectEqual(icmp.Code.net_unreachable, ip_h.payload[1]);

    var frame2: [512]u8 = undefined;
    const n2 = try buildEchoRequest(
        &frame2,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "y",
    );
    try fwd.handle(testing.io, frame2[0..n2], port_a);

    var out2: [512]u8 = undefined;
    const m2 = (try b.takeSent(&out2)).?;
    const eth2 = try ethernet.parse(out2[0..m2]);
    try testing.expect(eth2.dst.isBroadcast());
    try testing.expectEqual(ethernet.EtherType.arp, eth2.ethertype);
    const req = try arp.parse(eth2.payload);
    try testing.expectEqual(arp.Operation.request, req.operation);
    try testing.expect(req.sender_ip.eql(testIp("10.0.2.1")));
    try testing.expect(req.target_ip.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u64, 1), fwd.counters.arp_requests);
}

test "forwarder emits frag-needed above egress mtu" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    b.mtu = 100;
    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        &@as([100]u8, @splat(0x41)),
    );
    try fwd.handle(testing.io, frame[0..n], port_a);
    try testing.expectEqual(@as(usize, 0), b.queuedTx());

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(icmp.Type.destination_unreachable, ip_h.payload[0]);
    try testing.expectEqual(icmp.Code.frag_needed, ip_h.payload[1]);
    const mtu = (@as(u32, ip_h.payload[6]) << 8) | ip_h.payload[7];
    try testing.expectEqual(@as(u32, 100), mtu);
}

test "forwarder drops vlan tagged frames" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var plain: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &plain,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "vlan",
    );
    const plain_eth = try ethernet.parse(plain[0..n]);

    var tagged: [512]u8 = undefined;
    const hlen = try ethernet.write(
        &tagged,
        port_a_mac,
        host_a_mac,
        ethernet.EtherType.ipv4,
        100,
    );
    @memcpy(tagged[hlen..][0..plain_eth.payload.len], plain_eth.payload);

    try fwd.handle(testing.io, tagged[0 .. hlen + plain_eth.payload.len], port_a);
    try testing.expectEqual(@as(usize, 0), a.queuedTx());
    try testing.expectEqual(@as(usize, 0), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.dropped);
}

test "vlan-aware bridge tags and filters by port membership" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;

    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "vlan",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a", "pvid": 10 },
        \\    "b": { "kind": "l2", "device": "b", "pvid": 20, "tagged": [10, 20] }
        \\  },
        \\  "bridges": {
        \\    "br": { "ports": ["a", "b"], "vlan_aware": true }
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    var frame: [128]u8 = undefined;
    var hlen = try ethernet.write(&frame, host_b_mac, host_a_mac, 0x88b5, null);
    @memcpy(frame[hlen..][0..4], "vlan");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_a);

    var out: [512]u8 = undefined;
    const n = (try b.takeSent(&out)).?;
    const tagged = try ethernet.parse(out[0..n]);
    try testing.expectEqual(@as(?u16, 10), tagged.vlan);
    try testing.expectEqualSlices(u8, "vlan", tagged.payload);

    hlen = try ethernet.write(&frame, host_a_mac, host_b_mac, 0x88b5, 10);
    @memcpy(frame[hlen..][0..4], "back");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_b);
    const back_n = (try a.takeSent(&out)).?;
    const untagged = try ethernet.parse(out[0..back_n]);
    try testing.expectEqual(@as(?u16, null), untagged.vlan);
    try testing.expectEqualSlices(u8, "back", untagged.payload);

    hlen = try ethernet.write(&frame, host_a_mac, host_b_mac, 0x88b5, 20);
    @memcpy(frame[hlen..][0..4], "drop");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_b);
    try testing.expectEqual(@as(usize, 0), a.queuedTx());

    hlen = try ethernet.write(&frame, host_a_mac, host_b_mac, 0x88b5, null);
    @memcpy(frame[hlen..][0..4], "pvid");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_b);
    try testing.expectEqual(@as(usize, 0), a.queuedTx());
}

test "vlan-aware SVI replies and ARP cache are per vlan" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;

    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "vlan-svi",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a", "pvid": 10 },
        \\    "b": { "kind": "l2", "device": "b", "pvid": 20, "tagged": [10, 20] }
        \\  },
        \\  "bridges": {
        \\    "br": { "ports": ["a", "b"], "vlan_aware": true }
        \\  },
        \\  "interfaces": {
        \\    "lan0": { "bridge": "br", "address": "10.0.1.1/24", "vlan": 10 }
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    var frame: [128]u8 = undefined;
    var arp_buf: [28]u8 = undefined;
    _ = try arp.write(
        &arp_buf,
        .request,
        host_a_mac,
        testIp("10.0.1.9"),
        types.Mac.zero,
        testIp("10.0.1.1"),
    );
    var hlen = try ethernet.write(&frame, types.Mac.broadcast, host_a_mac, ethernet.EtherType.arp, null);
    @memcpy(frame[hlen..][0..arp_buf.len], &arp_buf);
    try fwd.handle(testing.io, frame[0 .. hlen + arp_buf.len], port_a);

    var out: [512]u8 = undefined;
    const n = (try a.takeSent(&out)).?;
    const reply = try ethernet.parse(out[0..n]);
    try testing.expectEqual(@as(?u16, null), reply.vlan);
    const reply_arp = try arp.parse(reply.payload);
    try testing.expectEqual(arp.Operation.reply, reply_arp.operation);
    try testing.expect(reply_arp.sender_mac.eql(port_a_mac));
    try testing.expect(reply_arp.sender_ip.eql(testIp("10.0.1.1")));
    try testing.expect(fwd.arp.getVlan(testIp("10.0.1.9"), 10) != null);

    _ = try arp.write(
        &arp_buf,
        .reply,
        host_b_mac,
        testIp("10.0.1.9"),
        port_b_mac,
        testIp("10.0.1.1"),
    );
    hlen = try ethernet.write(&frame, port_b_mac, host_b_mac, ethernet.EtherType.arp, 20);
    @memcpy(frame[hlen..][0..arp_buf.len], &arp_buf);
    try fwd.handle(testing.io, frame[0 .. hlen + arp_buf.len], port_b);

    const vlan10 = fwd.arp.getVlan(testIp("10.0.1.9"), 10).?;
    const vlan20 = fwd.arp.getVlan(testIp("10.0.1.9"), 20).?;
    try testing.expect(vlan10.mac.eql(host_a_mac));
    try testing.expect(vlan20.mac.eql(host_b_mac));
    try testing.expect(fwd.arp.getVlan(testIp("10.0.1.9"), 0) == null);
}

test "forwarder builds state from config" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;

    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };

    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "fwd",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "interfaces": {
        \\    "lan-a": { "port": "a", "address": "10.0.1.1/24" },
        \\    "lan-b": { "port": "b", "address": "10.0.2.1/24" }
        \\  },
        \\  "routes": [
        \\    { "dst": "0.0.0.0/0", "via": "10.0.1.254", "dev": "a", "metric": 100 }
        \\  ],
        \\  "nat": {
        \\    "masquerade": [ { "out": "lan-b" } ],
        \\    "port_forward": [ { "proto": "tcp", "ext_port": 8080, "to": "10.0.1.10:80" } ]
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();

    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    try testing.expectEqual(@as(usize, 2), fwd.local.items.len);
    try testing.expectEqual(@as(usize, 3), fwd.fib.count());

    const route = fwd.fib.lookup(testIp("8.8.8.8")).?;
    try testing.expect(route.next_hop.?.eql(testIp("10.0.1.254")));
    try testing.expect(route.port.eql(port_a));
    try testing.expect(route.metric == 100);
    try testing.expect(fwd.localForPeer(port_b, testIp("10.0.2.9"), 0) != null);
    try testing.expectEqual(@as(usize, 1), fwd.snat_rules.items.len);
    try testing.expect(fwd.snat_rules.items[0].port.eql(port_b));
    try testing.expect(fwd.snat_rules.items[0].addr.eql(testIp("10.0.2.1")));
    try testing.expectEqual(@as(usize, 1), fwd.forward_rules.items.len);
    try testing.expectEqual(@as(u8, 6), fwd.forward_rules.items[0].proto);
    try testing.expectEqual(@as(u16, 8080), fwd.forward_rules.items[0].ext_port);
    try testing.expect(fwd.forward_rules.items[0].to_addr.eql(testIp("10.0.1.10")));
    try testing.expectEqual(@as(u16, 80), fwd.forward_rules.items[0].to_port);
}

test "kernel offload bridge maps its veth trunk as one synthetic member" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var trunk = MemoryPort.init(testing.allocator, port_a, "vnatp0", 1500);
    defer trunk.deinit();
    trunk.mac = port_a_mac;

    const entries = [1]PortEntry{
        .{ .id = port_a, .config_name = "br", .port = trunk.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "offload",
        \\  "ports": {
        \\    "lan": { "kind": "l2", "device": "eth1", "pvid": 10, "tagged": [20] }
        \\  },
        \\  "bridges": {
        \\    "br": { "ports": ["lan"], "vlan_aware": true, "stp": true, "offload": "kernel" }
        \\  },
        \\  "interfaces": {
        \\    "lan0": { "bridge": "br", "address": "10.0.10.1/24", "vlan": 10 }
        \\  },
        \\  "firewall": {
        \\    "rules": [ { "action": "accept", "iif": "br" } ]
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    try testing.expectEqual(@as(usize, 1), fwd.bridges.items.len);
    const bridge = fwd.bridges.items[0];
    try testing.expectEqual(@as(usize, 1), bridge.members.len);
    try testing.expect(bridge.members[0].eql(port_a));
    try testing.expect(!bridge.stp);
    try testing.expectEqual(@as(usize, 0), bridge.stp_ports.len);
    try testing.expectEqual(@as(u16, 1), bridge.vlans[0].pvid);
    try testing.expectEqualSlices(u16, &.{ 10, 20 }, bridge.vlans[0].tagged);
    try testing.expectEqual(@as(usize, 1), fwd.local.items.len);
    try testing.expect(fwd.local.items[0].port.eql(port_a));
    try testing.expectEqual(@as(u16, 10), fwd.local.items[0].vlan);
    try testing.expectEqual(@as(usize, 1), fwd.firewall_rules.items.len);
    try testing.expectEqual(port_a, fwd.firewall_rules.items[0].iif.?.port);
}

test "firewall rules are ordered and match interfaces and addresses" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;
    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "fw",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "interfaces": {
        \\    "lan-a": { "port": "a", "address": "10.0.1.1/24" },
        \\    "lan-b": { "port": "b", "address": "10.0.2.1/24" }
        \\  },
        \\  "firewall": {
        \\    "default_forward": "drop",
        \\    "rules": [
        \\      { "action": "drop", "proto": "icmp", "src": "10.0.1.2/32" },
        \\      { "action": "accept", "proto": "icmp", "iif": "lan-a", "oif": "lan-b" }
        \\    ]
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    const dropped = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "no",
    );
    try fwd.handle(testing.io, frame[0..dropped], port_a);
    try testing.expectEqual(@as(usize, 0), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.firewall_dropped);
    try testing.expectEqual(@as(u64, 1), fwd.firewall_rules.items[0].packets);

    const allowed = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.3"),
        testIp("10.0.2.2"),
        64,
        "yes",
    );
    try fwd.handle(testing.io, frame[0..allowed], port_a);
    try testing.expectEqual(@as(usize, 1), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.firewall_rules.items[1].packets);
    try testing.expectEqual(@as(u64, 1), fwd.counters.forwarded);
}

test "firewall probe reports the matching rule or default policy" {
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "fw-probe",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "interfaces": {
        \\    "lan": { "port": "a" },
        \\    "wan": { "port": "b" }
        \\  },
        \\  "firewall": {
        \\    "default_in": "accept",
        \\    "default_forward": "drop",
        \\    "rules": [
        \\      { "action": "accept", "proto": "tcp", "dport": 443, "iif": "lan", "oif": "wan" },
        \\      { "action": "reject", "proto": "tcp", "dport": 8080 }
        \\    ]
        \\  }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();

    const accepted = try Forwarder.probeFirewallConfig(
        testing.allocator,
        testing.io,
        &parsed.config,
        .{
            .proto = ipv4.Protocol.tcp,
            .src = testIp("10.0.1.2"),
            .dst = testIp("10.0.2.2"),
            .dport = 443,
            .iif = "lan",
            .oif = "wan",
        },
    );
    try testing.expectEqual(@as(?usize, 0), accepted.rule);
    try testing.expectEqual(schema.FirewallAction.accept, accepted.action);

    const rejected = try Forwarder.probeFirewallConfig(
        testing.allocator,
        testing.io,
        &parsed.config,
        .{
            .proto = ipv4.Protocol.tcp,
            .src = testIp("10.0.1.2"),
            .dst = testIp("10.0.2.2"),
            .dport = 8080,
        },
    );
    try testing.expectEqual(@as(?usize, 1), rejected.rule);
    try testing.expectEqual(schema.FirewallAction.reject, rejected.action);

    const fallthrough = try Forwarder.probeFirewallConfig(
        testing.allocator,
        testing.io,
        &parsed.config,
        .{
            .proto = ipv4.Protocol.udp,
            .src = testIp("10.0.1.2"),
            .dst = testIp("10.0.2.2"),
            .dport = 53,
        },
    );
    try testing.expectEqual(@as(?usize, null), fallthrough.rule);
    try testing.expectEqual(schema.FirewallAction.drop, fallthrough.action);

    const inbound = try Forwarder.probeFirewallConfig(
        testing.allocator,
        testing.io,
        &parsed.config,
        .{
            .proto = ipv4.Protocol.icmp,
            .src = testIp("10.0.1.2"),
            .dst = testIp("10.0.1.1"),
            .hook = .input,
        },
    );
    try testing.expectEqual(@as(?usize, null), inbound.rule);
    try testing.expectEqual(schema.FirewallAction.accept, inbound.action);
}

test "icmp error rate limit drops excess replies" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();
    fwd.icmp_limiter = rate.Limiter.init(1);

    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        1,
        "ttl",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);
    try fwd.handle(testing.io, frame[0..n], port_a);
    try testing.expectEqual(@as(usize, 1), a.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_errors);
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_rate_limited);
}

test "arp rate limit drops excess requests" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();
    fwd.arp_limiter = rate.Limiter.init(1);

    var frame: [128]u8 = undefined;
    const n = try buildArpRequest(
        &frame,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.1.1"),
    );
    try fwd.handle(testing.io, frame[0..n], port_a);
    try fwd.handle(testing.io, frame[0..n], port_a);
    try testing.expectEqual(@as(usize, 1), a.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.arp_replies);
    try testing.expectEqual(@as(u64, 1), fwd.counters.arp_rate_limited);
}

test "rp_filter drops sources not reachable from the ingress port" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;
    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "rp",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "interfaces": {
        \\    "lan": { "port": "a", "address": "10.0.1.1/24" },
        \\    "wan": { "port": "b", "address": "10.0.2.1/24" }
        \\  },
        \\  "firewall": { "rp_filter": true, "default_forward": "accept" }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    const spoofed = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.9.9"),
        testIp("10.0.2.2"),
        64,
        "bad",
    );
    try fwd.handle(testing.io, frame[0..spoofed], port_a);
    try testing.expectEqual(@as(usize, 0), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.firewall_spoofed);

    const allowed = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "ok",
    );
    try fwd.handle(testing.io, frame[0..allowed], port_a);
    try testing.expectEqual(@as(usize, 1), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.firewall_spoofed);
}

test "bridge storm control drops excess flooded frames" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;

    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "storm",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a", "storm_control": 1 },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "bridges": { "br0": { "ports": ["a", "b"] } }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    var frame: [128]u8 = undefined;
    const hlen = try ethernet.write(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        0x88b5,
        null,
    );
    @memcpy(frame[hlen..][0..4], "floo");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_a);
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_a);
    try testing.expectEqual(@as(usize, 1), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.storm_dropped);
}

test "STP blocks an alternate port and forwards converged root ports" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    const port_c: types.PortId = .{ .value = 4 };
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;
    var c = MemoryPort.init(testing.allocator, port_c, "c", 1500);
    defer c.deinit();
    c.mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x0c } };

    const entries = [3]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
        .{ .id = port_c, .config_name = "c", .port = c.port() },
    };
    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "stp",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" },
        \\    "c": { "kind": "l2", "device": "c" }
        \\  },
        \\  "bridges": { "br0": { "ports": ["a", "b", "c"], "stp": true } }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    const bridge = &fwd.bridges.items[0];
    const root = stp.bridgeId(0x8000, .{ .bytes = .{ 0x02, 0, 0, 0, 0, 1 } });
    var frame: [128]u8 = undefined;
    const b_len = try writeStpTestFrame(&frame, root, 0, 0x0100);
    try fwd.handleAt(testing.io, frame[0..b_len], port_b, 10_000);
    const c_len = try writeStpTestFrame(&frame, root, 5, 0x0200);
    try fwd.handleAt(testing.io, frame[0..c_len], port_c, 10_000);

    try testing.expectEqual(StpPortRole.root, bridge.stp_ports[1].role);
    try testing.expectEqual(StpPortRole.alternate, bridge.stp_ports[2].role);
    try testing.expectEqual(StpPortState.blocking, bridge.stp_ports[2].state);
    try testing.expectEqual(StpPortState.listening, bridge.stp_ports[0].state);
    try testing.expectEqual(StpPortState.listening, bridge.stp_ports[1].state);

    fwd.stpTick(testing.io, 24_000);
    const b_len_2 = try writeStpTestFrame(&frame, root, 0, 0x0100);
    try fwd.handleAt(testing.io, frame[0..b_len_2], port_b, 24_000);
    const c_len_2 = try writeStpTestFrame(&frame, root, 5, 0x0200);
    try fwd.handleAt(testing.io, frame[0..c_len_2], port_c, 24_000);
    fwd.stpTick(testing.io, 38_000);
    const b_len_3 = try writeStpTestFrame(&frame, root, 0, 0x0100);
    try fwd.handleAt(testing.io, frame[0..b_len_3], port_b, 39_000);
    const c_len_3 = try writeStpTestFrame(&frame, root, 5, 0x0200);
    try fwd.handleAt(testing.io, frame[0..c_len_3], port_c, 39_000);
    fwd.stpTick(testing.io, 54_000);

    try testing.expectEqual(StpPortState.forwarding, bridge.stp_ports[0].state);
    try testing.expectEqual(StpPortState.forwarding, bridge.stp_ports[1].state);
    try testing.expectEqual(StpPortState.blocking, bridge.stp_ports[2].state);

    const hlen = try ethernet.write(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        0x88b5,
        null,
    );
    @memcpy(frame[hlen..][0..4], "stpd");
    const a_before = a.queuedTx();
    const b_before = b.queuedTx();
    const c_before = c.queuedTx();
    try fwd.handleAt(testing.io, frame[0 .. hlen + 4], port_c, 54_000);
    try testing.expectEqual(a_before, a.queuedTx());
    try testing.expectEqual(b_before, b.queuedTx());
    try testing.expectEqual(c_before, c.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.stp_filtered);

    try fwd.handleAt(testing.io, frame[0 .. hlen + 4], port_b, 54_000);
    try testing.expectEqual(a_before + 1, a.queuedTx());
    try testing.expectEqual(b_before, b.queuedTx());
    try testing.expectEqual(c_before, c.queuedTx());
    try testing.expectEqual(@as(u64, 6), fwd.counters.stp_bpdus_rx);
}

test "bridge forwards frames and serves dhcp on any member" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a = MemoryPort.init(testing.allocator, port_a, "a", 1500);
    defer a.deinit();
    a.mac = port_a_mac;
    var b = MemoryPort.init(testing.allocator, port_b, "b", 1500);
    defer b.deinit();
    b.mac = port_b_mac;

    const entries = [2]PortEntry{
        .{ .id = port_a, .config_name = "a", .port = a.port() },
        .{ .id = port_b, .config_name = "b", .port = b.port() },
    };

    const json =
        \\{
        \\  "version": 1,
        \\  "instance": "bridge",
        \\  "ports": {
        \\    "a": { "kind": "l2", "device": "a" },
        \\    "b": { "kind": "l2", "device": "b" }
        \\  },
        \\  "bridges": { "br0": { "ports": ["a", "b"] } },
        \\  "interfaces": { "lan": { "bridge": "br0", "address": "10.9.0.1/24" } },
        \\  "dhcp": [ { "iface": "lan", "pool": "10.9.0.100-10.9.0.101" } ]
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();
    var fwd = try Forwarder.fromConfig(testing.allocator, testing.io, &parsed.config, &entries);
    defer fwd.deinit();

    try testing.expectEqual(@as(usize, 1), fwd.bridges.items.len);
    try testing.expectEqual(@as(usize, 2), fwd.local.items.len);
    const route = fwd.fib.lookup(testIp("10.9.0.2")).?;
    try testing.expectEqual(@as(?u32, 0), route.bridge);

    var arp_req: [28]u8 = undefined;
    _ = try arp.write(&arp_req, .request, host_a_mac, testIp("10.9.0.2"), types.Mac.zero, testIp("10.9.0.1"));
    var frame: [128]u8 = undefined;
    var hlen = try ethernet.write(&frame, types.Mac.broadcast, host_a_mac, ethernet.EtherType.arp, null);
    @memcpy(frame[hlen..][0..arp_req.len], &arp_req);
    try fwd.handle(testing.io, frame[0 .. hlen + arp_req.len], port_a);

    var out: [512]u8 = undefined;
    const am = (try a.takeSent(&out)).?;
    const arp_eth = try ethernet.parse(out[0..am]);
    const arp_reply = try arp.parse(arp_eth.payload);
    try testing.expectEqual(arp.Operation.reply, arp_reply.operation);
    try testing.expect(arp_reply.sender_ip.eql(testIp("10.9.0.1")));

    var drain: [512]u8 = undefined;
    while (try b.takeSent(&drain) != null) {}

    hlen = try ethernet.write(&frame, types.Mac.broadcast, host_b_mac, 0x88b5, null);
    @memcpy(frame[hlen..][0..4], "test");
    try fwd.handle(testing.io, frame[0 .. hlen + 4], port_a);
    const bm = (try b.takeSent(&out)).?;
    const bridged = try ethernet.parse(out[0..bm]);
    try testing.expectEqual(@as(u16, 0x88b5), bridged.ethertype);
    try testing.expectEqualSlices(u8, "test", bridged.payload);
    try testing.expectEqual(@as(u64, 2), fwd.counters.bridged);

    var payload_buf: [512]u8 = undefined;
    const discover = try buildDhcpPayload(&payload_buf, .discover, 9, host_b_mac, null, null);
    var dhcp_frame: [512]u8 = undefined;
    const dn = try buildUdpFrame(
        &dhcp_frame,
        types.Mac.broadcast,
        host_b_mac,
        types.Ipv4.unspecified,
        types.Ipv4.limited_broadcast,
        68,
        67,
        64,
        discover,
    );
    try fwd.handle(testing.io, dhcp_frame[0..dn], port_b);
    flushDhcpOffers(&fwd);
    const offer_n = try takeIpv4Sent(&b, &out);
    const offer_eth = try ethernet.parse(out[0..offer_n]);
    const offer_ip = try ipv4.parse(offer_eth.payload);
    const offer = try dhcp_message.Message.parse(offer_ip.payload[8..]);
    try testing.expectEqual(dhcp_message.MessageType.offer, offer.messageType().?);
}

fn buildTcpSegment(buf: []u8) void {
    @memset(buf[0..20], 0);
    writeU16(buf, 0, 1234);
    writeU16(buf, 2, 80);
    writeU16(buf, 4, 1);
    buf[12] = 0x50;
    buf[13] = 0x02;
    writeU16(buf, 14, 0xffff);
}

test "forwarder repairs offloaded tcp checksums" {
    const src = testIp("10.0.1.2");
    const dst = testIp("10.0.2.2");

    var tcp: [20]u8 = undefined;
    buildTcpSegment(&tcp);
    var packet: [64]u8 = undefined;
    const n = try ipv4.write(&packet, src, dst, ipv4.Protocol.tcp, 64, 7, &tcp);

    writeU16(&packet, 20 + 16, 0xdead);
    fixTransportChecksum(packet[0..n]);
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(src, dst, ipv4.Protocol.tcp, packet[20..n]),
    );
}

test "forwarder repairs offloaded udp checksums" {
    const src = testIp("10.0.1.2");
    const dst = testIp("10.0.2.2");

    var udp: [12]u8 = @splat(0);
    writeU16(&udp, 0, 1234);
    writeU16(&udp, 2, 53);
    writeU16(&udp, 4, 12);
    @memcpy(udp[8..12], "dns!");

    var packet: [64]u8 = undefined;
    const n = try ipv4.write(&packet, src, dst, ipv4.Protocol.udp, 64, 7, &udp);
    writeU16(&packet, 20 + 6, 0xbeef);

    fixTransportChecksum(packet[0..n]);
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(src, dst, ipv4.Protocol.udp, packet[20..n]),
    );
}

test "forwarder announces local addresses with gratuitous arp" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.announce(testing.io);
    try testing.expectEqual(@as(u64, 2), fwd.counters.garps);

    var out: [64]u8 = undefined;
    const n = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..n]);
    try testing.expect(eth.dst.isBroadcast());
    try testing.expect(eth.src.eql(port_a_mac));
    try testing.expectEqual(ethernet.EtherType.arp, eth.ethertype);

    const packet = try arp.parse(eth.payload);
    try testing.expectEqual(arp.Operation.request, packet.operation);
    try testing.expect(packet.sender_ip.eql(testIp("10.0.1.1")));
    try testing.expect(packet.target_ip.eql(testIp("10.0.1.1")));
    try testing.expect(packet.target_mac.isZero());
    try testing.expect(packet.sender_mac.eql(port_a_mac));
}

test "tun ingress forwards to l2" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var t: MemoryPort = undefined;
    var a: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setupTun(&t, &a, &entries, &fwd);
    defer fwd.deinit();
    defer a.deinit();
    defer t.deinit();

    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = nowMs(testing.io),
    });

    var packet: [512]u8 = undefined;
    const n = try buildIpEcho(&packet, testIp("10.0.3.2"), testIp("10.0.2.2"), 64, "tun");
    try fwd.handle(testing.io, packet[0..n], port_tun);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_a_mac));
    try testing.expect(eth.src.eql(port_a_mac));
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);

    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expect(ip_h.src.eql(testIp("10.0.3.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqualSlices(u8, "tun", ip_h.payload[8..]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.forwarded);
}

test "tun ingress replies to local echo without ethernet" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var t: MemoryPort = undefined;
    var a: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setupTun(&t, &a, &entries, &fwd);
    defer fwd.deinit();
    defer a.deinit();
    defer t.deinit();

    var packet: [512]u8 = undefined;
    const n = try buildIpEcho(&packet, testIp("10.0.3.2"), testIp("10.0.3.1"), 64, "hello");
    try fwd.handle(testing.io, packet[0..n], port_tun);

    var out: [512]u8 = undefined;
    const m = (try t.takeSent(&out)).?;
    const ip_h = try ipv4.parse(out[0..m]);
    try testing.expect(ip_h.src.eql(testIp("10.0.3.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.3.2")));
    try testing.expectEqual(icmp.Type.echo_reply, ip_h.payload[0]);
    try testing.expectEqualSlices(u8, "hello", ip_h.payload[8..]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.local_delivered);
}

test "tun ingress emits icmp error without ethernet" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var t: MemoryPort = undefined;
    var a: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setupTun(&t, &a, &entries, &fwd);
    defer fwd.deinit();
    defer a.deinit();
    defer t.deinit();

    var packet: [512]u8 = undefined;
    const n = try buildIpEcho(&packet, testIp("10.0.3.2"), testIp("10.9.9.9"), 64, "lost");
    try fwd.handle(testing.io, packet[0..n], port_tun);

    var out: [512]u8 = undefined;
    const m = (try t.takeSent(&out)).?;
    const ip_h = try ipv4.parse(out[0..m]);
    try testing.expect(ip_h.src.eql(testIp("10.0.3.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.3.2")));
    try testing.expectEqual(icmp.Type.destination_unreachable, ip_h.payload[0]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_errors);
}

test "l2 ingress forwards to tun without ethernet" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var t: MemoryPort = undefined;
    var a: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setupTun(&t, &a, &entries, &fwd);
    defer fwd.deinit();
    defer a.deinit();
    defer t.deinit();

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.3.2"),
        64,
        "vpn",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try t.takeSent(&out)).?;
    const ip_h = try ipv4.parse(out[0..m]);
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.3.2")));
    try testing.expectEqualSlices(u8, "vpn", ip_h.payload[8..]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.forwarded);
}

test "forwarder queues packet until arp resolves" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    var frame: [512]u8 = undefined;
    const n = try buildEchoRequest(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        64,
        "queued",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const arp_len = (try b.takeSent(&out)).?;
    const arp_eth = try ethernet.parse(out[0..arp_len]);
    try testing.expectEqual(ethernet.EtherType.arp, arp_eth.ethertype);
    const request = try arp.parse(arp_eth.payload);
    try testing.expectEqual(arp.Operation.request, request.operation);
    try testing.expect(request.target_ip.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u64, 1), fwd.counters.pending_queued);
    try testing.expectEqual(@as(u64, 0), fwd.counters.forwarded);

    var reply: [64]u8 = undefined;
    const reply_len = try buildArpReply(
        &reply,
        host_b_mac,
        testIp("10.0.2.2"),
        port_b_mac,
        testIp("10.0.2.1"),
    );
    try fwd.handle(testing.io, reply[0..reply_len], port_b);

    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_b_mac));
    try testing.expect(eth.src.eql(port_b_mac));
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqualSlices(u8, "queued", ip_h.payload[8..]);
    try testing.expectEqual(@as(u64, 1), fwd.counters.pending_flushed);
    try testing.expectEqual(@as(u64, 1), fwd.counters.forwarded);
}

fn wrapIpFrame(buf: []u8, eth_dst: types.Mac, eth_src: types.Mac, ip_packet: []const u8) !usize {
    const hlen = try ethernet.write(buf, eth_dst, eth_src, ethernet.EtherType.ipv4, null);
    @memcpy(buf[hlen..][0..ip_packet.len], ip_packet);
    return hlen + ip_packet.len;
}

fn buildDhcpPayload(
    buf: []u8,
    typ: dhcp_message.MessageType,
    xid: u32,
    mac: types.Mac,
    requested: ?types.Ipv4,
    server_id: ?types.Ipv4,
) ![]u8 {
    var builder = try dhcp_message.Builder.init(buf, dhcp_message.op_request, typ, xid, mac, 0x8000);
    if (requested) |ip| try builder.addIpv4(50, ip);
    if (server_id) |ip| try builder.addIpv4(54, ip);
    return builder.finish();
}

fn buildDhcpReply(
    buf: []u8,
    typ: dhcp_message.MessageType,
    xid: u32,
    mac: types.Mac,
    yiaddr: types.Ipv4,
    server_id: types.Ipv4,
    lease_seconds: u32,
) ![]u8 {
    var builder = try dhcp_message.Builder.init(buf, dhcp_message.op_reply, typ, xid, mac, 0x8000);
    builder.setYiaddr(yiaddr);
    try builder.addIpv4(54, server_id);
    try builder.addIpv4(1, .{ .value = 0xffffff00 });
    try builder.addIpv4(3, server_id);
    try builder.addU32(51, lease_seconds);
    try builder.addU32(58, lease_seconds / 2);
    try builder.addU32(59, lease_seconds * 7 / 8);
    return builder.finish();
}

fn buildUdpFrame(
    buf: []u8,
    eth_dst: types.Mac,
    eth_src: types.Mac,
    src: types.Ipv4,
    dst: types.Ipv4,
    sport: u16,
    dport: u16,
    ttl: u8,
    payload: []const u8,
) !usize {
    var udp: [1024]u8 = undefined;
    const udp_len = 8 + payload.len;
    writeU16(&udp, 0, sport);
    writeU16(&udp, 2, dport);
    writeU16(&udp, 4, @intCast(udp_len));
    writeU16(&udp, 6, 0);
    @memcpy(udp[8..udp_len], payload);

    var ip_buf: [1200]u8 = undefined;
    const ip_len = try ipv4.write(&ip_buf, src, dst, ipv4.Protocol.udp, ttl, 0x4444, udp[0..udp_len]);
    const ip_h = try ipv4.parse(ip_buf[0..ip_len]);
    const udp_payload = ip_buf[ip_h.header_len..ip_len];
    var sum = transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.udp, udp_payload);
    if (sum == 0) sum = 0xffff;
    writeU16(udp_payload, 6, sum);
    return wrapIpFrame(buf, eth_dst, eth_src, ip_buf[0..ip_len]);
}

fn buildUdpPacket(
    buf: []u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    sport: u16,
    dport: u16,
    payload: []const u8,
) ![]u8 {
    var udp: [1024]u8 = undefined;
    const udp_len = 8 + payload.len;
    writeU16(&udp, 0, sport);
    writeU16(&udp, 2, dport);
    writeU16(&udp, 4, @intCast(udp_len));
    writeU16(&udp, 6, 0);
    @memcpy(udp[8..udp_len], payload);

    const ip_len = try ipv4.write(buf, src, dst, ipv4.Protocol.udp, 64, 0x6666, udp[0..udp_len]);
    const ip_h = try ipv4.parse(buf[0..ip_len]);
    const udp_payload = buf[ip_h.header_len..ip_len];
    var sum = transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.udp, udp_payload);
    if (sum == 0) sum = 0xffff;
    writeU16(udp_payload, 6, sum);
    return buf[0..ip_len];
}

fn buildTcpPacket(
    buf: []u8,
    src: types.Ipv4,
    dst: types.Ipv4,
    sport: u16,
    dport: u16,
    flags: u8,
) ![]u8 {
    var tcp: [20]u8 = @splat(0);
    writeU16(&tcp, 0, sport);
    writeU16(&tcp, 2, dport);
    tcp[12] = 0x50;
    tcp[13] = flags;
    writeU16(&tcp, 14, 0xffff);

    const ip_len = try ipv4.write(buf, src, dst, ipv4.Protocol.tcp, 64, 0x6666, &tcp);
    const ip_h = try ipv4.parse(buf[0..ip_len]);
    const tcp_payload = buf[ip_h.header_len..ip_len];
    writeU16(tcp_payload, 16, 0);
    writeU16(
        tcp_payload,
        16,
        transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.tcp, tcp_payload),
    );
    return buf[0..ip_len];
}

fn buildIcmpErrorFrame(
    buf: []u8,
    eth_dst: types.Mac,
    eth_src: types.Mac,
    outer_src: types.Ipv4,
    outer_dst: types.Ipv4,
    quoted_packet: []const u8,
    typ: u8,
    code: u8,
) !usize {
    var msg: [1024]u8 = undefined;
    const m = try icmp.writeError(&msg, typ, code, quoted_packet, 0);
    var ip_buf: [1200]u8 = undefined;
    const n = try ipv4.write(
        &ip_buf,
        outer_src,
        outer_dst,
        ipv4.Protocol.icmp,
        64,
        0x7777,
        msg[0..m],
    );
    return wrapIpFrame(buf, eth_dst, eth_src, ip_buf[0..n]);
}

fn buildTcpFrame(
    buf: []u8,
    eth_dst: types.Mac,
    eth_src: types.Mac,
    src: types.Ipv4,
    dst: types.Ipv4,
    sport: u16,
    dport: u16,
    flags: u8,
) !usize {
    var tcp: [20]u8 = @splat(0);
    writeU16(&tcp, 0, sport);
    writeU16(&tcp, 2, dport);
    tcp[12] = 0x50;
    tcp[13] = flags;
    writeU16(&tcp, 14, 0xffff);

    var ip_buf: [1200]u8 = undefined;
    const ip_len = try ipv4.write(&ip_buf, src, dst, ipv4.Protocol.tcp, 64, 0x5555, &tcp);
    const ip_h = try ipv4.parse(ip_buf[0..ip_len]);
    const tcp_payload = ip_buf[ip_h.header_len..ip_len];
    writeU16(tcp_payload, 16, 0);
    writeU16(
        tcp_payload,
        16,
        transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.tcp, tcp_payload),
    );
    return wrapIpFrame(buf, eth_dst, eth_src, ip_buf[0..ip_len]);
}

test "snat translates udp and restores the reply" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        40000,
        9999,
        64,
        "hello",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 40000), readU16(ip_h.payload, 0));
    try testing.expectEqual(@as(u16, 9999), readU16(ip_h.payload, 2));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.packet[0..ip_h.header_len]));
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.udp, ip_h.payload),
    );

    const rn = try buildUdpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        9999,
        40000,
        64,
        "world",
    );
    try fwd.handle(testing.io, frame[0..rn], port_b);

    const rm = (try a.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.src.eql(testIp("10.0.2.2")));
    try testing.expect(rip.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u16, 9999), readU16(rip.payload, 0));
    try testing.expectEqual(@as(u16, 40000), readU16(rip.payload, 2));
    try testing.expectEqual(@as(u32, 1), fwd.conntrack.count);
    try testing.expectEqual(@as(u64, 1), fwd.counters.snat_packets);
    try testing.expectEqual(@as(u64, 1), fwd.conntrack.counters.created);
    try testing.expectEqual(@as(u64, 1), fwd.conntrack.counters.hits);
}

test "snat allocates distinct ports for colliding sources" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = nowMs(testing.io),
    });

    var frame: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    var ports: [2]u16 = undefined;

    for ([_]types.Ipv4{ testIp("10.0.1.2"), testIp("10.0.1.3") }, 0..) |src, i| {
        const n = try buildUdpFrame(
            &frame,
            port_a_mac,
            host_a_mac,
            src,
            testIp("10.0.2.2"),
            40000,
            9999,
            64,
            "x",
        );
        try fwd.handle(testing.io, frame[0..n], port_a);
        const m = (try b.takeSent(&out)).?;
        const eth = try ethernet.parse(out[0..m]);
        const ip_h = try ipv4.parse(eth.payload);
        try testing.expect(ip_h.src.eql(testIp("10.0.2.1")));
        ports[i] = readU16(ip_h.payload, 0);
    }

    try testing.expectEqual(@as(u16, 40000), ports[0]);
    try testing.expect(ports[1] != 40000);
    try testing.expectEqual(@as(u32, 2), fwd.conntrack.count);
}

test "snat translates icmp echo identifiers and reverses replies" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var icmp_buf: [64]u8 = undefined;
    const icmp_len = try icmp.writeEchoRequest(&icmp_buf, 0x10, 1, "ping");
    var ip_buf: [128]u8 = undefined;
    const ip_len = try ipv4.write(
        &ip_buf,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        ipv4.Protocol.icmp,
        64,
        0x6666,
        icmp_buf[0..icmp_len],
    );

    var frame: [512]u8 = undefined;
    var n = try wrapIpFrame(&frame, port_a_mac, host_a_mac, ip_buf[0..ip_len]);
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.1")));
    const translated_id = readU16(ip_h.payload, 4);
    try testing.expect(translated_id >= 1024);
    try testing.expect(translated_id != 0x10);

    var reply_icmp: [64]u8 = undefined;
    const reply_len = try icmp.writeEchoReply(&reply_icmp, ip_h.payload);
    var reply_ip: [128]u8 = undefined;
    const reply_ip_len = try ipv4.write(
        &reply_ip,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        ipv4.Protocol.icmp,
        64,
        0x7777,
        reply_icmp[0..reply_len],
    );
    n = try wrapIpFrame(&frame, port_b_mac, host_b_mac, reply_ip[0..reply_ip_len]);
    try fwd.handle(testing.io, frame[0..n], port_b);

    const rm = (try a.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.src.eql(testIp("10.0.2.2")));
    try testing.expect(rip.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(icmp.Type.echo_reply, rip.payload[0]);
    try testing.expectEqual(@as(u16, 0x10), readU16(rip.payload, 4));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(rip.payload));
}

test "snat tracks tcp state and rewrites ports" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    var n = try buildTcpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        40000,
        80,
        TCP_SYN,
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.1")));
    try testing.expectEqual(@as(u16, 40000), readU16(ip_h.payload, 0));
    try testing.expectEqual(@as(u16, 80), readU16(ip_h.payload, 2));
    try testing.expectEqual(TCP_SYN, ip_h.payload[13]);
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.tcp, ip_h.payload),
    );

    n = try buildTcpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        80,
        40000,
        TCP_SYN | TCP_ACK,
    );
    try fwd.handle(testing.io, frame[0..n], port_b);

    const rm = (try a.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u16, 80), readU16(rip.payload, 0));
    try testing.expectEqual(@as(u16, 40000), readU16(rip.payload, 2));

    const key = conntrack_mod.FlowKey{
        .zone = port_a.value,
        .proto = ipv4.Protocol.tcp,
        .src = testIp("10.0.1.2"),
        .sport = 40000,
        .dst = testIp("10.0.2.2"),
        .dport = 80,
    };
    try testing.expectEqual(conntrack_mod.State.established, fwd.conntrack.lookup(key).?.state);
}

test "dnat forwards to an internal target and restores the reply" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    // An explicit port forward must work even when the default forwarding
    // policy drops new flows.
    fwd.firewall.default_forward = .drop;
    try fwd.addForwardRule(ipv4.Protocol.tcp, 8080, testIp("10.0.1.10"), 80);
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.1.10"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildTcpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        40000,
        8080,
        0x02,
    );
    try fwd.handle(testing.io, frame[0..n], port_b);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_a_mac));
    try testing.expect(eth.src.eql(port_a_mac));
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.10")));
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expectEqual(@as(u16, 40000), readU16(ip_h.payload, 0));
    try testing.expectEqual(@as(u16, 80), readU16(ip_h.payload, 2));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.packet[0..ip_h.header_len]));
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(ip_h.src, ip_h.dst, ipv4.Protocol.tcp, ip_h.payload),
    );

    const rn = try buildTcpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.10"),
        testIp("10.0.2.2"),
        80,
        40000,
        0x12,
    );
    try fwd.handle(testing.io, frame[0..rn], port_a);

    const rm = (try b.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    try testing.expect(reth.dst.eql(host_b_mac));
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.src.eql(testIp("10.0.2.1")));
    try testing.expect(rip.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 8080), readU16(rip.payload, 0));
    try testing.expectEqual(@as(u16, 40000), readU16(rip.payload, 2));
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(rip.src, rip.dst, ipv4.Protocol.tcp, rip.payload),
    );
    try testing.expectEqual(@as(u32, 1), fwd.conntrack.count);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dnat_packets);
    try testing.expectEqual(@as(u64, 0), fwd.counters.snat_packets);
}

test "hairpin dnat snats back out the ingress port" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addForwardRule(ipv4.Protocol.tcp, 8080, testIp("10.0.1.10"), 80);
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.1.10"), .{
        .mac = host_b_mac,
        .port = port_a,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildTcpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.1.1"),
        40000,
        8080,
        0x02,
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    try testing.expect(eth.dst.eql(host_b_mac));
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.10")));
    try testing.expectEqual(@as(u16, 40000), readU16(ip_h.payload, 0));
    try testing.expectEqual(@as(u16, 80), readU16(ip_h.payload, 2));

    const rn = try buildTcpFrame(
        &frame,
        port_a_mac,
        host_b_mac,
        testIp("10.0.1.10"),
        testIp("10.0.1.1"),
        80,
        40000,
        0x12,
    );
    try fwd.handle(testing.io, frame[0..rn], port_a);

    const rm = (try a.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    try testing.expect(reth.dst.eql(host_a_mac));
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.src.eql(testIp("10.0.1.1")));
    try testing.expect(rip.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u16, 8080), readU16(rip.payload, 0));
    try testing.expectEqual(@as(u16, 40000), readU16(rip.payload, 2));
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(rip.src, rip.dst, ipv4.Protocol.tcp, rip.payload),
    );
    try testing.expectEqual(@as(u32, 1), fwd.conntrack.count);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dnat_packets);
    try testing.expectEqual(@as(u64, 1), fwd.counters.snat_packets);
}

test "dnat translates udp port forwards" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addForwardRule(ipv4.Protocol.udp, 5353, testIp("10.0.1.10"), 9999);
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.1.10"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        40000,
        5353,
        64,
        "dns?",
    );
    try fwd.handle(testing.io, frame[0..n], port_b);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.10")));
    try testing.expectEqual(@as(u16, 40000), readU16(ip_h.payload, 0));
    try testing.expectEqual(@as(u16, 9999), readU16(ip_h.payload, 2));

    const rn = try buildUdpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.10"),
        testIp("10.0.2.2"),
        9999,
        40000,
        64,
        "answer",
    );
    try fwd.handle(testing.io, frame[0..rn], port_a);

    const rm = (try b.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.src.eql(testIp("10.0.2.1")));
    try testing.expect(rip.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 5353), readU16(rip.payload, 0));
    try testing.expectEqual(@as(u16, 40000), readU16(rip.payload, 2));
    try testing.expectEqual(@as(u32, 1), fwd.conntrack.count);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dnat_packets);
}

test "snat translates icmp errors quoting the translated flow" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        40000,
        9999,
        64,
        "hello",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var quoted_buf: [512]u8 = undefined;
    const quoted = try buildUdpPacket(
        &quoted_buf,
        testIp("10.0.2.1"),
        testIp("10.0.2.2"),
        40000,
        9999,
        "",
    );
    const en = try buildIcmpErrorFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        quoted,
        icmp.Type.destination_unreachable,
        icmp.Code.frag_needed,
    );
    try fwd.handle(testing.io, frame[0..en], port_b);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.2")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u8, 63), ip_h.ttl);
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.packet[0..ip_h.header_len]));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.payload));
    try testing.expectEqual(icmp.Type.destination_unreachable, ip_h.payload[0]);
    try testing.expectEqual(icmp.Code.frag_needed, ip_h.payload[1]);

    const quoted_out = ip_h.payload[8..];
    const quoted_hl: usize = @as(usize, quoted_out[0] & 0x0f) * 4;
    const quoted_src: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted_out[12..16], .big) };
    const quoted_dst: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted_out[16..20], .big) };
    const quoted_l4 = quoted_out[quoted_hl..];
    try testing.expect(quoted_src.eql(testIp("10.0.1.2")));
    try testing.expect(quoted_dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 40000), readU16(quoted_l4, 0));
    try testing.expectEqual(@as(u16, 9999), readU16(quoted_l4, 2));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(quoted_out[0..quoted_hl]));
    try testing.expectEqual(
        @as(u16, 0),
        transportChecksum(quoted_src, quoted_dst, ipv4.Protocol.udp, quoted_l4),
    );
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_translated);
}

test "dnat translates icmp errors quoting the translated flow" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addForwardRule(ipv4.Protocol.tcp, 8080, testIp("10.0.1.10"), 80);
    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.1.10"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildTcpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.2.1"),
        40000,
        8080,
        0x02,
    );
    try fwd.handle(testing.io, frame[0..n], port_b);

    var quoted_buf: [512]u8 = undefined;
    const quoted = try buildTcpPacket(
        &quoted_buf,
        testIp("10.0.2.2"),
        testIp("10.0.1.10"),
        40000,
        80,
        0x02,
    );
    const en = try buildIcmpErrorFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.10"),
        testIp("10.0.2.2"),
        quoted,
        icmp.Type.destination_unreachable,
        icmp.Code.host_unreachable,
    );
    try fwd.handle(testing.io, frame[0..en], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.2.1")));
    try testing.expect(ip_h.dst.eql(testIp("10.0.2.2")));
    try testing.expectEqual(@as(u16, 0), ipv4.checksum(ip_h.payload));

    const quoted_out = ip_h.payload[8..];
    const quoted_hl: usize = @as(usize, quoted_out[0] & 0x0f) * 4;
    const quoted_src: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted_out[12..16], .big) };
    const quoted_dst: types.Ipv4 = .{ .value = std.mem.readInt(u32, quoted_out[16..20], .big) };
    const quoted_l4 = quoted_out[quoted_hl..];
    try testing.expect(quoted_src.eql(testIp("10.0.2.2")));
    try testing.expect(quoted_dst.eql(testIp("10.0.2.1")));
    try testing.expectEqual(@as(u16, 40000), readU16(quoted_l4, 0));
    try testing.expectEqual(@as(u16, 8080), readU16(quoted_l4, 2));
    try testing.expectEqual(@as(u64, 1), fwd.counters.icmp_translated);
}

test "dhcp server offers and acks a lease" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addDhcpServer(.{
        .port = port_a,
        .server_ip = testIp("10.0.1.1"),
        .prefix = testPrefix("10.0.1.1/24"),
        .pool = types.parseIpRange("10.0.1.100-10.0.1.101") catch unreachable,
        .lease_seconds = 3600,
        .dns = testIp("10.0.1.1"),
    });

    var payload_buf: [512]u8 = undefined;
    const discover = try buildDhcpPayload(&payload_buf, .discover, 7, host_a_mac, null, null);
    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        types.Ipv4.unspecified,
        types.Ipv4.limited_broadcast,
        68,
        67,
        64,
        discover,
    );
    try fwd.handle(testing.io, frame[0..n], port_a);
    flushDhcpOffers(&fwd);

    var out: [512]u8 = undefined;
    const m = try takeIpv4Sent(&a, &out);
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    const offer = try dhcp_message.Message.parse(ip_h.payload[8..]);
    try testing.expectEqual(dhcp_message.MessageType.offer, offer.messageType().?);
    try testing.expectEqual(@as(u32, 0x0a000164), offer.yiaddr.value);
    try testing.expectEqual(@as(u32, 0x0a000101), offer.options.serverId().?.value);

    const request = try buildDhcpPayload(
        &payload_buf,
        .request,
        7,
        host_a_mac,
        .{ .value = 0x0a000164 },
        testIp("10.0.1.1"),
    );
    const rn = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        types.Ipv4.unspecified,
        types.Ipv4.limited_broadcast,
        68,
        67,
        64,
        request,
    );
    try fwd.handle(testing.io, frame[0..rn], port_a);

    const am = (try a.takeSent(&out)).?;
    const ack_eth = try ethernet.parse(out[0..am]);
    const ack_ip = try ipv4.parse(ack_eth.payload);
    const ack = try dhcp_message.Message.parse(ack_ip.payload[8..]);
    try testing.expectEqual(dhcp_message.MessageType.ack, ack.messageType().?);
    try testing.expectEqual(@as(u32, 0x0a000164), ack.yiaddr.value);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dhcp_offers);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dhcp_acks);
}

test "dhcp probes a candidate before offering and declines conflicts" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addDhcpServer(.{
        .port = port_a,
        .server_ip = testIp("10.0.1.1"),
        .prefix = testPrefix("10.0.1.1/24"),
        .pool = types.parseIpRange("10.0.1.100-10.0.1.101") catch unreachable,
        .lease_seconds = 3600,
        .dns = testIp("10.0.1.1"),
    });

    var payload_buf: [512]u8 = undefined;
    const discover = try buildDhcpPayload(&payload_buf, .discover, 21, host_a_mac, null, null);
    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        types.Ipv4.unspecified,
        types.Ipv4.limited_broadcast,
        68,
        67,
        64,
        discover,
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const pn = (try a.takeSent(&out)).?;
    const probe_eth = try ethernet.parse(out[0..pn]);
    try testing.expectEqual(ethernet.EtherType.arp, probe_eth.ethertype);
    const probe = try arp.parse(probe_eth.payload);
    try testing.expect(probe.target_ip.eql(testIp("10.0.1.100")));

    try fwd.arp.put(testing.allocator, testIp("10.0.1.100"), .{
        .mac = host_b_mac,
        .port = port_a,
        .updated_ms = nowMs(testing.io),
    });
    flushDhcpOffers(&fwd);
    try testing.expectEqual(@as(?usize, null), try a.takeSent(&out));
    try testing.expectEqual(@as(u64, 1), fwd.counters.dhcp_conflicts);
    try testing.expectEqual(@as(usize, 1), fwd.dhcp_servers.items[0].leaseCount(.declined));
}

test "dhcp client validates xid and server id and schedules renewal" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addDhcpClient(testing.io, port_a, host_a_mac, false);
    const client = &fwd.dhcp_clients.items[0];
    client.state = .selecting;

    const server = testIp("10.0.1.1");
    const offered = testIp("10.0.1.100");
    var payload_buf: [512]u8 = undefined;
    var frame: [512]u8 = undefined;

    const offer = try buildDhcpReply(&payload_buf, .offer, client.xid, host_a_mac, offered, server, 3600);
    const on = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        server,
        types.Ipv4.limited_broadcast,
        67,
        68,
        64,
        offer,
    );
    try fwd.handle(testing.io, frame[0..on], port_a);
    try testing.expectEqual(DhcpClientState.requesting, client.state);

    const wrong_xid = try buildDhcpReply(&payload_buf, .ack, client.xid ^ 1, host_a_mac, offered, server, 3600);
    const wn = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        server,
        types.Ipv4.limited_broadcast,
        67,
        68,
        64,
        wrong_xid,
    );
    try fwd.handle(testing.io, frame[0..wn], port_a);
    try testing.expectEqual(DhcpClientState.requesting, client.state);

    const wrong_server = try buildDhcpReply(
        &payload_buf,
        .ack,
        client.xid,
        host_a_mac,
        offered,
        testIp("10.0.1.254"),
        3600,
    );
    const sn = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        testIp("10.0.1.254"),
        types.Ipv4.limited_broadcast,
        67,
        68,
        64,
        wrong_server,
    );
    try fwd.handle(testing.io, frame[0..sn], port_a);
    try testing.expectEqual(DhcpClientState.requesting, client.state);

    const ack = try buildDhcpReply(&payload_buf, .ack, client.xid, host_a_mac, offered, server, 3600);
    const an = try buildUdpFrame(
        &frame,
        types.Mac.broadcast,
        host_a_mac,
        server,
        types.Ipv4.limited_broadcast,
        67,
        68,
        64,
        ack,
    );
    try fwd.handle(testing.io, frame[0..an], port_a);
    try testing.expectEqual(DhcpClientState.bound, client.state);
    try testing.expect(client.configured);
    try testing.expect(client.renew_at_ms > 0);
    try testing.expect(client.rebind_at_ms > client.renew_at_ms);
    try testing.expect(client.lease_expires_ms > client.rebind_at_ms);
    try testing.expectEqual(@as(u64, 1), fwd.counters.dhcp_client_bound);

    const now = client.renew_at_ms;
    fwd.tickDhcpClients(testing.io, now);
    try testing.expectEqual(DhcpClientState.renewing, client.state);

    var out: [512]u8 = undefined;
    const m = (try a.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(offered));
    const renewal = try dhcp_message.Message.parse(ip_h.payload[8..]);
    try testing.expectEqual(dhcp_message.MessageType.request, renewal.messageType().?);
    try testing.expect(renewal.ciaddr.eql(offered));
    try testing.expect(renewal.options.requestedIp() == null);
    try testing.expect(renewal.options.serverId() == null);
}

test "forwarder tracks non-nat flows without rewriting" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    const now = nowMs(testing.io);
    try fwd.arp.put(testing.allocator, testIp("10.0.2.2"), .{
        .mac = host_b_mac,
        .port = port_b,
        .updated_ms = now,
    });
    try fwd.arp.put(testing.allocator, testIp("10.0.1.2"), .{
        .mac = host_a_mac,
        .port = port_a,
        .updated_ms = now,
    });

    var frame: [512]u8 = undefined;
    const n = try buildUdpFrame(
        &frame,
        port_a_mac,
        host_a_mac,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        40000,
        9999,
        64,
        "x",
    );
    try fwd.handle(testing.io, frame[0..n], port_a);

    var out: [512]u8 = undefined;
    const m = (try b.takeSent(&out)).?;
    const eth = try ethernet.parse(out[0..m]);
    const ip_h = try ipv4.parse(eth.payload);
    try testing.expect(ip_h.src.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u32, 1), fwd.conntrack.count);

    const rn = try buildUdpFrame(
        &frame,
        port_b_mac,
        host_b_mac,
        testIp("10.0.2.2"),
        testIp("10.0.1.2"),
        9999,
        40000,
        64,
        "y",
    );
    try fwd.handle(testing.io, frame[0..rn], port_b);

    const rm = (try a.takeSent(&out)).?;
    const reth = try ethernet.parse(out[0..rm]);
    const rip = try ipv4.parse(reth.payload);
    try testing.expect(rip.dst.eql(testIp("10.0.1.2")));
    try testing.expectEqual(@as(u64, 1), fwd.conntrack.counters.hits);
}

test "snat drops fragments instead of leaking private sources" {
    const MemoryPort = @import("../port/memory.zig").MemoryPort;
    var a: MemoryPort = undefined;
    var b: MemoryPort = undefined;
    var entries: [2]PortEntry = undefined;
    var fwd: Forwarder = undefined;
    try setup(&a, &b, &entries, &fwd);
    defer fwd.deinit();
    defer b.deinit();
    defer a.deinit();

    try fwd.addSnatRule(port_b, testIp("10.0.2.1"));

    var ip_buf: [128]u8 = undefined;
    const ip_len = try ipv4.writeFlags(
        &ip_buf,
        testIp("10.0.1.2"),
        testIp("10.0.2.2"),
        ipv4.Protocol.udp,
        64,
        0x8888,
        0x2000,
        "fragment",
    );
    var frame: [512]u8 = undefined;
    const n = try wrapIpFrame(&frame, port_a_mac, host_a_mac, ip_buf[0..ip_len]);
    try fwd.handle(testing.io, frame[0..n], port_a);

    try testing.expectEqual(@as(usize, 0), b.queuedTx());
    try testing.expectEqual(@as(u64, 1), fwd.counters.nat_unsupported);
}
