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
const ipv4 = @import("ipv4.zig");
const arp = @import("arp.zig");
const icmp = @import("icmp.zig");
const fib = @import("fib.zig");
const conntrack_mod = @import("../nat/conntrack.zig");
const nat_mod = @import("../nat/nat.zig");

const PortError = @import("../errors.zig").PortError;

pub const conntrack_default_entries: u32 = 65_536;
pub const conntrack_small_entries: u32 = 4_096;

pub const arp_ttl_ms: i64 = 300_000;
pub const arp_request_interval_ms: i64 = 1_000;
pub const arp_pending_ttl_ms: i64 = 1_000;
const pending_slots = 32;
const pending_packet_max = 1600;

const PendingPacket = struct {
    used: bool = false,
    port: types.PortId = .{ .value = 0 },
    next_hop: types.Ipv4 = .{ .value = 0 },
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
};

pub const Counters = struct {
    rx_frames: u64 = 0,
    forwarded: u64 = 0,
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
    nat_unsupported: u64 = 0,
};

pub const Forwarder = struct {
    gpa: std.mem.Allocator,
    ports: []const PortEntry,
    fib: fib.Fib = .{},
    arp: arp.Cache = .{},
    local: std.ArrayListUnmanaged(LocalAddr) = .empty,
    arp_misses: std.AutoHashMapUnmanaged(u32, i64) = .empty,
    pending: [pending_slots]PendingPacket = [_]PendingPacket{.{}} ** pending_slots,
    conntrack: conntrack_mod.Conntrack,
    snat_rules: std.ArrayListUnmanaged(nat_mod.Rule) = .empty,
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
        try self.arp_misses.ensureTotalCapacity(gpa, 64);
        return self;
    }

    pub fn deinit(self: *Forwarder) void {
        self.fib.deinit(self.gpa);
        self.arp.deinit(self.gpa);
        self.local.deinit(self.gpa);
        self.arp_misses.deinit(self.gpa);
        self.snat_rules.deinit(self.gpa);
        self.conntrack.deinit();
    }

    pub fn addLocal(self: *Forwarder, prefix: types.Prefix4, port: types.PortId) PortError!void {
        try self.local.append(self.gpa, .{ .prefix = prefix, .port = port });
    }

    pub fn addRoute(self: *Forwarder, route: fib.Route) PortError!void {
        try self.fib.add(self.gpa, route);
    }

    pub fn addSnatRule(self: *Forwarder, port: types.PortId, addr: types.Ipv4) PortError!void {
        try self.snat_rules.append(self.gpa, .{ .port = port, .addr = addr });
    }

    pub fn tick(self: *Forwarder, io: std.Io) void {
        const now = nowMs(io);
        if (now - self.conntrack.last_gc_ms >= conntrack_mod.gc_interval_ms) {
            self.conntrack.gc(now);
        }
    }

    pub fn fromConfig(
        gpa: std.mem.Allocator,
        cfg: *const schema.Config,
        ports: []const PortEntry,
    ) PortError!Forwarder {
        var self = try initInner(gpa, ports, conntrack_default_entries);
        errdefer self.deinit();

        var it = cfg.interfaces.iterator();
        while (it.next()) |entry| {
            const itf = entry.value_ptr.*;
            const port_name = itf.port orelse continue;
            const port_entry = findPort(ports, port_name) orelse return error.NotFound;
            const address = itf.address orelse continue;
            if (std.mem.eql(u8, address, "dhcp")) continue;

            const prefix = types.Prefix4.parse(address) catch return error.InvalidArgument;
            try self.addLocal(prefix, port_entry.id);
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
            const port_entry = findRoutePort(cfg, ports, dev) orelse return error.NotFound;

            try self.addRoute(.{
                .prefix = .{ .addr = dst.network(), .len = dst.len },
                .next_hop = next_hop,
                .port = port_entry.id,
                .metric = route.metric,
            });
        }

        for (cfg.nat.masquerade) |masquerade| {
            const rule = resolveMasquerade(cfg, self.local.items, ports, masquerade.out) orelse
                return error.InvalidArgument;
            try self.addSnatRule(rule.port, rule.addr);
        }

        return self;
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
            self.sendL2(io, local.port, types.Mac.broadcast, ethernet.EtherType.arp, &payload) catch
                continue;
            self.counters.garps += 1;
        }
    }

    pub fn handle(
        self: *Forwarder,
        io: std.Io,
        frame: []const u8,
        ingress: types.PortId,
    ) PortError!void {
        self.counters.rx_frames += 1;
        const now = nowMs(io);
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
            try self.handleIpv4(io, null, ip, ingress);
            return;
        }

        const eth = ethernet.parse(frame) catch {
            self.counters.dropped += 1;
            return;
        };
        if (eth.vlan != null) {
            // VLAN forwarding is R5; dropping keeps tagged traffic from leaking
            // into the untagged bridge.
            self.counters.dropped += 1;
            return;
        }

        switch (eth.ethertype) {
            ethernet.EtherType.arp => try self.handleArp(io, eth, ingress),
            ethernet.EtherType.ipv4 => {
                const ip = ipv4.parse(eth.payload) catch {
                    self.counters.dropped += 1;
                    return;
                };
                try self.handleIpv4(io, eth, ip, ingress);
            },
            else => self.counters.dropped += 1,
        }
    }

    fn handleArp(
        self: *Forwarder,
        io: std.Io,
        eth: ethernet.Header,
        ingress: types.PortId,
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

        const learned = !packet.sender_ip.isUnspecified() and !packet.sender_mac.isZero();
        if (learned) {
            self.arp.put(self.gpa, packet.sender_ip, .{
                .mac = packet.sender_mac,
                .port = ingress,
                .updated_ms = nowMs(io),
            }) catch {};
            _ = self.arp_misses.remove(packet.sender_ip.value);
        }

        if (packet.operation == .request) {
            if (self.localOn(packet.target_ip, ingress)) |local| {
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
                    try self.sendL2(io, ingress, packet.sender_mac, ethernet.EtherType.arp, &reply);
                    self.counters.arp_replies += 1;
                }
            }
        }

        if (learned) {
            try self.flushPending(io, ingress, packet.sender_ip, packet.sender_mac);
        }
    }

    fn handleIpv4(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
    ) PortError!void {
        const total: usize = ip.total_len;
        const now = nowMs(io);
        const is_local = self.isLocal(ip.dst);
        const flow_key = flowKey(ip, ingress.value);

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

        // A reply to a NAT address is destined to a local IP but must be
        // reverse-translated and forwarded, not delivered to the router.
        if (is_local) {
            const forwardable = if (entry) |found|
                direction == .reply and found.nat != null
            else
                false;
            if (!forwardable) {
                try self.handleLocal(io, eth, ip, ingress);
                return;
            }
        }

        if (!is_local and (ip.dst.isMulticast() or ip.dst.isUnspecified() or
            ip.dst.eql(types.Ipv4.limited_broadcast)))
        {
            self.counters.dropped += 1;
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
                if (found.nat != null) {
                    if (!nat_mod.rewriteDestination(packet, found.original.src, found.original.sport)) {
                        self.counters.dropped += 1;
                        return;
                    }
                    ipm = ipv4.parse(packet) catch {
                        self.counters.dropped += 1;
                        return;
                    };
                }
            }
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
            );
            return;
        };

        const egress = self.portById(route.port) orelse {
            self.counters.dropped += 1;
            return;
        };
        const egress_info = egress.port.info();
        if (ipm.total_len > egress_info.mtu) {
            self.counters.dropped += 1;
            try self.sendError(
                io,
                eth,
                ipm,
                ingress,
                icmp.Type.destination_unreachable,
                icmp.Code.frag_needed,
                egress_info.mtu,
            );
            return;
        }

        if (entry) |found| {
            if (direction == .original) {
                if (found.nat) |nat_info| {
                    if (!nat_mod.rewriteSource(packet, nat_info.snat_addr, nat_info.snat_port)) {
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
        } else if (flow_key) |key| {
            if (self.snatAddrFor(route.port)) |nat_addr| {
                if (ipm.src.eql(nat_addr)) {
                    const reply_key = makeReplyKey(key, key.src, key.sport, route.port.value);
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
                    const reply_key = makeReplyKey(key, nat_addr, nat_port, route.port.value);
                    const nat_info = conntrack_mod.Nat{
                        .snat_addr = nat_addr,
                        .snat_port = nat_port,
                    };
                    const created = self.conntrack.create(
                        key,
                        reply_key,
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
                const reply_key = makeReplyKey(key, key.src, key.sport, route.port.value);
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
        const arp_entry = self.arp.getFresh(next_hop, route.port, now, arp_ttl_ms) orelse {
            try self.sendArpRequest(io, route.port, next_hop);
            if (!self.enqueuePending(route.port, next_hop, ipm.packet[0..total], now)) {
                self.counters.dropped += 1;
                self.counters.pending_dropped += 1;
            }
            return;
        };

        var out: [2048]u8 = undefined;
        const hlen = ethernet.write(
            &out,
            arp_entry.mac,
            egress_info.mac,
            ethernet.EtherType.ipv4,
            null,
        ) catch {
            self.counters.dropped += 1;
            return;
        };
        if (total > out.len - hlen) {
            self.counters.dropped += 1;
            return;
        }
        @memcpy(out[hlen..][0..total], ipm.packet[0..total]);
        ipv4.decrementTtl(out[hlen..][0..total]) catch {
            self.counters.dropped += 1;
            return;
        };
        fixTransportChecksum(out[hlen..][0..total]);
        try egress.port.write(io, out[0 .. hlen + total]);
        self.counters.forwarded += 1;
    }

    fn handleLocal(
        self: *Forwarder,
        io: std.Io,
        eth: ?ethernet.Header,
        ip: ipv4.Header,
        ingress: types.PortId,
    ) PortError!void {
        if (ip.protocol != ipv4.Protocol.icmp or ip.payload.len < 8 or
            ip.payload[0] != icmp.Type.echo_request)
        {
            self.counters.dropped += 1;
            return;
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

        var frame_buf: [2048]u8 = undefined;
        const hlen = ethernet.write(
            &frame_buf,
            l2.src,
            info.mac,
            ethernet.EtherType.ipv4,
            null,
        ) catch {
            self.counters.dropped += 1;
            return;
        };
        if (ip_len > frame_buf.len - hlen) {
            self.counters.dropped += 1;
            return;
        }
        @memcpy(frame_buf[hlen..][0..ip_len], ip_buf[0..ip_len]);
        try entry.port.write(io, frame_buf[0 .. hlen + ip_len]);
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
    ) PortError!void {
        if (ip.fragmentOffset() != 0) return;
        if (ip.src.isUnspecified() or ip.src.isMulticast() or
            ip.src.eql(types.Ipv4.limited_broadcast)) return;
        if (ip.protocol == ipv4.Protocol.icmp and ip.payload.len >= 1) {
            const t = ip.payload[0];
            if (t != icmp.Type.echo_request and t != icmp.Type.echo_reply) return;
        }

        const local = self.localForPeer(ingress, ip.src) orelse return;
        const entry = self.portById(ingress) orelse return;
        const info = entry.port.info();

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

        var frame_buf: [1200]u8 = undefined;
        const hlen = ethernet.write(
            &frame_buf,
            l2.src,
            info.mac,
            ethernet.EtherType.ipv4,
            null,
        ) catch return;
        if (ip_len > frame_buf.len - hlen) return;
        @memcpy(frame_buf[hlen..][0..ip_len], ip_buf[0..ip_len]);
        try entry.port.write(io, frame_buf[0 .. hlen + ip_len]);
        self.counters.icmp_errors += 1;
    }

    fn enqueuePending(
        self: *Forwarder,
        port: types.PortId,
        next_hop: types.Ipv4,
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
    ) PortError!void {
        const entry = self.portById(port) orelse return;
        const info = entry.port.info();
        if (info.mac.isZero()) return;

        for (&self.pending) |*slot| {
            if (!slot.used or !slot.port.eql(port) or !slot.next_hop.eql(next_hop)) continue;

            const len: usize = slot.len;
            var packet: [pending_packet_max]u8 = undefined;
            @memcpy(packet[0..len], slot.bytes[0..len]);
            slot.used = false;

            ipv4.decrementTtl(packet[0..len]) catch {
                self.counters.pending_dropped += 1;
                continue;
            };
            fixTransportChecksum(packet[0..len]);
            self.sendL2(io, port, next_mac, ethernet.EtherType.ipv4, packet[0..len]) catch {
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
    ) PortError!void {
        const entry = self.portById(egress) orelse return error.NotFound;
        const info = entry.port.info();
        if (info.kind == .tun or info.mac.isZero()) return;

        const now = nowMs(io);
        if (self.arp_misses.get(target.value)) |last| {
            if (now - last < arp_request_interval_ms) return;
        }
        try self.arp_misses.put(self.gpa, target.value, now);

        const local = self.localForPeer(egress, target) orelse return;
        var payload: [28]u8 = undefined;
        _ = arp.write(
            &payload,
            .request,
            info.mac,
            local.prefix.addr,
            types.Mac.zero,
            target,
        ) catch return;
        try self.sendL2(io, egress, types.Mac.broadcast, ethernet.EtherType.arp, &payload);
        self.counters.arp_requests += 1;
    }

    fn sendL2(
        self: *Forwarder,
        io: std.Io,
        egress: types.PortId,
        dst: types.Mac,
        ethertype: u16,
        payload: []const u8,
    ) PortError!void {
        const entry = self.portById(egress) orelse return error.NotFound;
        const info = entry.port.info();
        if (info.mac.isZero()) return error.Unsupported;

        var frame: [2048]u8 = undefined;
        const hlen = ethernet.write(&frame, dst, info.mac, ethertype, null) catch
            return error.FrameTooLarge;
        if (payload.len > frame.len - hlen) return error.FrameTooLarge;
        @memcpy(frame[hlen..][0..payload.len], payload);
        try entry.port.write(io, frame[0 .. hlen + payload.len]);
    }

    fn isLocal(self: *const Forwarder, ip: types.Ipv4) bool {
        for (self.local.items) |local| {
            if (local.prefix.addr.value == ip.value) return true;
        }
        return false;
    }

    fn localOn(self: *const Forwarder, ip: types.Ipv4, port: types.PortId) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port) and local.prefix.addr.value == ip.value) return local;
        }
        return null;
    }

    fn localForPort(self: *const Forwarder, port: types.PortId) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port)) return local;
        }
        return null;
    }

    fn localForPeer(self: *const Forwarder, port: types.PortId, peer: types.Ipv4) ?LocalAddr {
        for (self.local.items) |local| {
            if (local.port.eql(port) and local.prefix.contains(peer)) return local;
        }
        return self.localForPort(port);
    }

    fn snatAddrFor(self: *const Forwarder, port: types.PortId) ?types.Ipv4 {
        for (self.snat_rules.items) |rule| {
            if (rule.port.eql(port)) return rule.addr;
        }
        return null;
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

fn flowKey(ip: ipv4.Header, zone: u32) ?conntrack_mod.FlowKey {
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
        };
    }
    return null;
}

fn makeReplyKey(
    original: conntrack_mod.FlowKey,
    nat_addr: types.Ipv4,
    nat_port: u16,
    reply_zone: u32,
) conntrack_mod.FlowKey {
    if (original.proto == ipv4.Protocol.icmp) {
        return .{
            .zone = reply_zone,
            .proto = original.proto,
            .src = original.dst,
            .sport = nat_port,
            .dst = nat_addr,
            .dport = 0,
        };
    }
    return .{
        .zone = reply_zone,
        .proto = original.proto,
        .src = original.dst,
        .sport = original.dport,
        .dst = nat_addr,
        .dport = nat_port,
    };
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
        const port_name = itf.port orelse return null;
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
    try fwd.addLocal(testPrefix("10.0.1.1/24"), port_a);
    try fwd.addLocal(testPrefix("10.0.2.1/24"), port_b);
    try fwd.addRoute(.{ .prefix = testNet("10.0.1.0/24"), .port = port_a, .kind = .connected });
    try fwd.addRoute(.{ .prefix = testNet("10.0.2.0/24"), .port = port_b, .kind = .connected });
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
    try fwd.addLocal(testPrefix("10.0.1.1/24"), port_a);
    try fwd.addLocal(testPrefix("10.0.3.1/24"), port_tun);
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
        &([_]u8{0x41} ** 100),
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
        \\  "nat": { "masquerade": [ { "out": "lan-b" } ] }
        \\}
    ;
    var parsed = try config_parse.parse(testing.allocator, json);
    defer parsed.deinit();

    var fwd = try Forwarder.fromConfig(testing.allocator, &parsed.config, &entries);
    defer fwd.deinit();

    try testing.expectEqual(@as(usize, 2), fwd.local.items.len);
    try testing.expectEqual(@as(usize, 3), fwd.fib.count());

    const route = fwd.fib.lookup(testIp("8.8.8.8")).?;
    try testing.expect(route.next_hop.?.eql(testIp("10.0.1.254")));
    try testing.expect(route.port.eql(port_a));
    try testing.expect(route.metric == 100);
    try testing.expect(fwd.localForPeer(port_b, testIp("10.0.2.9")) != null);
    try testing.expectEqual(@as(usize, 1), fwd.snat_rules.items.len);
    try testing.expect(fwd.snat_rules.items[0].port.eql(port_b));
    try testing.expect(fwd.snat_rules.items[0].addr.eql(testIp("10.0.2.1")));
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

    var udp: [12]u8 = [_]u8{0} ** 12;
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
    var tcp: [20]u8 = [_]u8{0} ** 20;
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
