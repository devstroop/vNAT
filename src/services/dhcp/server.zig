//! DHCPv4 server state machine: pool allocation, offers, binding, decline and
//! release. The datapath owns packet I/O; this module only produces replies.

const std = @import("std");
const types = @import("../../types.zig");
const message = @import("message.zig");

pub const offer_timeout_ms: i64 = 60_000;
pub const decline_timeout_ms: i64 = 10 * 60_000;
pub const max_leases: u32 = 65_536;

pub const Error = error{
    OutOfMemory,
    InvalidPool,
    OutOfSpace,
    InvalidArgument,
    BadCookie,
    BadHeader,
    BadOption,
    Truncated,
};

pub const Reservation = struct {
    mac: types.Mac,
    ip: types.Ipv4,
};

pub const Config = struct {
    port: types.PortId,
    server_ip: types.Ipv4,
    prefix: types.Prefix4,
    pool: types.IpRange,
    lease_seconds: u32,
    dns: types.Ipv4,
    domain: ?[]const u8 = null,
    mtu: ?u16 = null,
    ntp: ?types.Ipv4 = null,
    reservations: []const Reservation = &.{},
};

pub const Counters = struct {
    discovers: u64 = 0,
    offers: u64 = 0,
    requests: u64 = 0,
    acks: u64 = 0,
    naks: u64 = 0,
    declines: u64 = 0,
    releases: u64 = 0,
    informs: u64 = 0,
    expired: u64 = 0,
    dropped: u64 = 0,
};

pub const State = enum { free, offered, bound, declined };

const Lease = struct {
    state: State = .free,
    ip: types.Ipv4 = .{},
    mac: types.Mac = .{},
    expires_ms: i64 = 0,
};

pub const Reply = struct {
    payload: []const u8,
    dst_ip: types.Ipv4,
    dst_mac: types.Mac,
    typ: message.MessageType,
};

pub const LeaseSnapshot = struct {
    state: State,
    ip: types.Ipv4,
    mac: types.Mac,
    expires_ms: i64,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    leases: []Lease,
    reservations: []Reservation,
    counters: Counters = .{},

    pub fn init(gpa: std.mem.Allocator, cfg: Config) Error!Server {
        if (cfg.lease_seconds == 0) return error.InvalidArgument;
        if (cfg.pool.first.value > cfg.pool.last.value) return error.InvalidPool;
        if (!cfg.prefix.contains(cfg.pool.first) or !cfg.prefix.contains(cfg.pool.last)) {
            return error.InvalidPool;
        }
        const pool_count = @as(u64, cfg.pool.last.value) - cfg.pool.first.value + 1;
        if (pool_count > max_leases) return error.InvalidPool;

        for (cfg.reservations, 0..) |reservation, i| {
            if (!cfg.prefix.contains(reservation.ip)) return error.InvalidArgument;
            if (reservation.ip.eql(cfg.server_ip)) return error.InvalidArgument;
            if (reservation.mac.isZero() or reservation.mac.isMulticast() or
                reservation.mac.isBroadcast())
            {
                return error.InvalidArgument;
            }
            for (cfg.reservations[0..i]) |other| {
                if (reservation.mac.eql(other.mac)) return error.InvalidArgument;
                if (reservation.ip.eql(other.ip)) return error.InvalidArgument;
            }
        }

        var extra: u64 = 0;
        for (cfg.reservations) |reservation| {
            if (reservation.ip.value < cfg.pool.first.value or
                reservation.ip.value > cfg.pool.last.value)
            {
                extra += 1;
            }
        }
        const count = pool_count + extra;
        if (count > max_leases) return error.InvalidPool;

        const reservations = try gpa.dupe(Reservation, cfg.reservations);
        errdefer gpa.free(reservations);
        const leases = try gpa.alloc(Lease, @intCast(count));
        errdefer gpa.free(leases);
        for (leases, 0..) |*lease, i| {
            lease.* = .{
                .state = .free,
                .ip = .{ .value = cfg.pool.first.value + @as(u32, @intCast(i)) },
            };
        }
        var next = @as(usize, @intCast(pool_count));
        for (cfg.reservations) |reservation| {
            if (reservation.ip.value >= cfg.pool.first.value and
                reservation.ip.value <= cfg.pool.last.value)
            {
                continue;
            }
            leases[next] = .{ .state = .free, .ip = reservation.ip };
            next += 1;
        }
        return .{
            .gpa = gpa,
            .cfg = cfg,
            .leases = leases,
            .reservations = reservations,
        };
    }

    pub fn deinit(self: *Server) void {
        self.gpa.free(self.leases);
        self.gpa.free(self.reservations);
        self.* = undefined;
    }

    pub fn handle(self: *Server, request: message.Message, out: []u8, now_ms: i64) Error!?Reply {
        if (request.op != message.op_request) return null;
        const mac = request.clientMac() orelse {
            self.counters.dropped += 1;
            return null;
        };
        if (!request.giaddr.isUnspecified()) {
            // Relayed DHCP is out of scope for v1.
            self.counters.dropped += 1;
            return null;
        }
        if (request.options.serverId()) |server_id| {
            if (!server_id.eql(self.cfg.server_ip)) return null;
        }

        const typ = request.messageType() orelse {
            self.counters.dropped += 1;
            return null;
        };
        const requested = request.options.requestedIp();

        switch (typ) {
            .discover => {
                self.counters.discovers += 1;
                const ip = self.offer(mac, requested, now_ms) orelse {
                    self.counters.dropped += 1;
                    return null;
                };
                self.counters.offers += 1;
                const payload = try self.buildReply(out, .offer, request, mac, ip, true);
                return self.makeReply(payload, .offer, request, ip, false);
            },
            .request => {
                self.counters.requests += 1;
                const wanted = requested orelse
                    (if (request.ciaddr.isUnspecified()) null else request.ciaddr);
                const ip = wanted orelse {
                    self.counters.naks += 1;
                    const payload = try self.buildReply(out, .nak, request, mac, .{}, false);
                    return self.makeReply(payload, .nak, request, .{}, true);
                };
                if (!self.commit(mac, ip, now_ms)) {
                    self.counters.naks += 1;
                    const payload = try self.buildReply(out, .nak, request, mac, .{}, false);
                    return self.makeReply(payload, .nak, request, .{}, true);
                }
                self.counters.acks += 1;
                const payload = try self.buildReply(out, .ack, request, mac, ip, true);
                return self.makeReply(payload, .ack, request, ip, false);
            },
            .decline => {
                self.counters.declines += 1;
                const ip = requested orelse request.ciaddr;
                if (!ip.isUnspecified()) self.decline(mac, ip, now_ms);
                return null;
            },
            .release => {
                self.counters.releases += 1;
                const ip = if (request.ciaddr.isUnspecified()) requested else request.ciaddr;
                if (ip) |addr| self.release(mac, addr);
                return null;
            },
            .inform => {
                self.counters.informs += 1;
                if (request.ciaddr.isUnspecified()) {
                    self.counters.dropped += 1;
                    return null;
                }
                const payload = try self.buildReply(out, .ack, request, mac, .{}, false);
                return self.makeReply(payload, .ack, request, request.ciaddr, false);
            },
            else => {
                self.counters.dropped += 1;
                return null;
            },
        }
    }

    pub fn gc(self: *Server, now_ms: i64) void {
        for (self.leases) |*lease| {
            if (lease.state == .free) continue;
            if (now_ms >= lease.expires_ms) {
                lease.state = .free;
                lease.mac = .{};
                lease.expires_ms = 0;
                self.counters.expired += 1;
            }
        }
    }

    pub fn leaseCapacity(self: *const Server) usize {
        return self.leases.len;
    }

    /// Copies non-free leases into `out`; returns the number written. The
    /// caller owns `out` and must size it to at least `leaseCapacity()`.
    pub fn snapshot(self: *const Server, out: []LeaseSnapshot) usize {
        var count: usize = 0;
        for (self.leases) |lease| {
            if (lease.state == .free) continue;
            if (count >= out.len) break;
            out[count] = .{
                .state = lease.state,
                .ip = lease.ip,
                .mac = lease.mac,
                .expires_ms = lease.expires_ms,
            };
            count += 1;
        }
        return count;
    }

    /// Restores one lease from a persisted snapshot. Expired offers/bindings
    /// and records that conflict with the current pool or reservations are
    /// ignored so a stale database cannot widen the pool.
    pub fn restore(self: *Server, record: LeaseSnapshot, now_ms: i64) bool {
        if (record.state == .free) return false;
        if (record.state == .declined) {
            const lease = self.leaseForIp(record.ip) orelse return false;
            if (lease.state != .free) return false;
            lease.state = .declined;
            lease.mac = .{};
            lease.expires_ms = record.expires_ms;
            return record.expires_ms > now_ms;
        }
        if (record.mac.isZero() or record.mac.isMulticast() or record.mac.isBroadcast()) {
            return false;
        }
        if (record.expires_ms <= now_ms) return false;
        if (self.reservationFor(record.mac)) |reservation| {
            if (!reservation.ip.eql(record.ip)) return false;
        } else if (self.reservedForOther(record.ip, record.mac)) {
            return false;
        }
        if (self.leaseForMac(record.mac)) |existing| {
            if (!existing.ip.eql(record.ip)) return false;
        }
        const lease = self.leaseForIp(record.ip) orelse return false;
        if (lease.state == .declined and !lease.mac.isZero()) return false;
        if (lease.state != .free and !lease.mac.eql(record.mac)) return false;
        lease.state = record.state;
        lease.mac = record.mac;
        lease.expires_ms = record.expires_ms;
        return true;
    }

    pub fn leaseCount(self: *const Server, state: State) usize {
        var count: usize = 0;
        for (self.leases) |lease| {
            if (lease.state == state) count += 1;
        }
        return count;
    }

    fn offer(self: *Server, mac: types.Mac, requested: ?types.Ipv4, now_ms: i64) ?types.Ipv4 {
        self.gc(now_ms);
        if (self.reservationFor(mac)) |reservation| {
            const lease = self.leaseForIp(reservation.ip) orelse return null;
            if (lease.state == .free or
                ((lease.state == .offered or lease.state == .bound) and lease.mac.eql(mac)))
            {
                markOffered(lease, mac, now_ms);
                return lease.ip;
            }
            return null;
        }
        if (self.leaseForMac(mac)) |lease| return lease.ip;

        if (requested) |ip| {
            if (self.leaseForIp(ip)) |lease| {
                if (lease.state == .free and !self.reservedForOther(ip, mac)) {
                    markOffered(lease, mac, now_ms);
                    return lease.ip;
                }
            }
        }
        for (self.leases) |*lease| {
            if (lease.state != .free) continue;
            if (self.reservedForOther(lease.ip, mac)) continue;
            markOffered(lease, mac, now_ms);
            return lease.ip;
        }
        return null;
    }

    fn commit(self: *Server, mac: types.Mac, ip: types.Ipv4, now_ms: i64) bool {
        self.gc(now_ms);
        if (self.reservationFor(mac)) |reservation| {
            if (!reservation.ip.eql(ip)) return false;
        } else if (self.reservedForOther(ip, mac)) {
            return false;
        }
        const lease = self.leaseForIp(ip) orelse return false;
        switch (lease.state) {
            .free => {
                lease.state = .bound;
                lease.mac = mac;
                lease.expires_ms = now_ms + leaseMs(self.cfg.lease_seconds);
                return true;
            },
            .declined => return false,
            .offered, .bound => {
                if (!lease.mac.eql(mac)) return false;
                lease.state = .bound;
                lease.expires_ms = now_ms + leaseMs(self.cfg.lease_seconds);
                return true;
            },
        }
    }

    fn decline(self: *Server, mac: types.Mac, ip: types.Ipv4, now_ms: i64) void {
        if (self.reservedForOther(ip, mac)) return;
        const lease = self.leaseForIp(ip) orelse return;
        if (lease.state != .free and !lease.mac.eql(mac)) return;
        lease.state = .declined;
        lease.mac = .{};
        lease.expires_ms = now_ms + decline_timeout_ms;
    }

    fn release(self: *Server, mac: types.Mac, ip: types.Ipv4) void {
        if (self.reservedForOther(ip, mac)) return;
        const lease = self.leaseForIp(ip) orelse return;
        if (lease.state == .free or !lease.mac.eql(mac)) return;
        lease.state = .free;
        lease.mac = .{};
        lease.expires_ms = 0;
    }

    fn reservationFor(self: *const Server, mac: types.Mac) ?Reservation {
        for (self.reservations) |reservation| {
            if (reservation.mac.eql(mac)) return reservation;
        }
        return null;
    }

    fn reservedForOther(self: *const Server, ip: types.Ipv4, mac: types.Mac) bool {
        for (self.reservations) |reservation| {
            if (reservation.ip.eql(ip) and !reservation.mac.eql(mac)) return true;
        }
        return false;
    }

    fn markOffered(lease: *Lease, mac: types.Mac, now_ms: i64) void {
        lease.state = .offered;
        lease.mac = mac;
        lease.expires_ms = now_ms + offer_timeout_ms;
    }

    fn leaseForMac(self: *Server, mac: types.Mac) ?*Lease {
        for (self.leases) |*lease| {
            if (lease.state == .free or lease.state == .declined) continue;
            if (lease.mac.eql(mac)) return lease;
        }
        return null;
    }

    fn leaseForIp(self: *Server, ip: types.Ipv4) ?*Lease {
        for (self.leases) |*lease| {
            if (lease.ip.eql(ip)) return lease;
        }
        return null;
    }

    fn buildReply(
        self: *Server,
        out: []u8,
        typ: message.MessageType,
        request: message.Message,
        mac: types.Mac,
        yiaddr: types.Ipv4,
        include_lease: bool,
    ) Error![]u8 {
        var builder = message.Builder.init(out, message.op_reply, typ, request.xid, mac, request.flags) catch
            return error.OutOfSpace;
        builder.setYiaddr(yiaddr);
        try addIpv4(&builder, 54, self.cfg.server_ip);

        if (typ == .nak) {
            try builder.addOption(56, "address unavailable");
        } else {
            try addIpv4(&builder, 1, .{ .value = self.cfg.prefix.mask() });
            try addIpv4(&builder, 3, self.cfg.server_ip);
            try addIpv4(&builder, 6, self.cfg.dns);
            if (self.cfg.domain) |domain| try builder.addOption(15, domain);
            try addIpv4(&builder, 28, broadcastAddress(self.cfg.prefix));
            if (self.cfg.mtu) |mtu| try builder.addU16(26, mtu);
            if (self.cfg.ntp) |ntp| try addIpv4(&builder, 42, ntp);
            if (include_lease) {
                try builder.addU32(51, self.cfg.lease_seconds);
                try builder.addU32(58, self.cfg.lease_seconds / 2);
                try builder.addU32(59, self.cfg.lease_seconds * 7 / 8);
            }
        }
        return builder.finish() catch return error.OutOfSpace;
    }

    fn makeReply(
        self: *Server,
        payload: []const u8,
        typ: message.MessageType,
        request: message.Message,
        yiaddr: types.Ipv4,
        force_broadcast: bool,
    ) Reply {
        _ = self;
        const mac = request.clientMac().?;
        if (force_broadcast or request.flags & 0x8000 != 0) {
            return .{
                .payload = payload,
                .dst_ip = types.Ipv4.limited_broadcast,
                .dst_mac = types.Mac.broadcast,
                .typ = typ,
            };
        }
        if (!request.ciaddr.isUnspecified()) {
            return .{
                .payload = payload,
                .dst_ip = request.ciaddr,
                .dst_mac = mac,
                .typ = typ,
            };
        }
        if (!yiaddr.isUnspecified()) {
            return .{
                .payload = payload,
                .dst_ip = yiaddr,
                .dst_mac = mac,
                .typ = typ,
            };
        }
        return .{
            .payload = payload,
            .dst_ip = types.Ipv4.limited_broadcast,
            .dst_mac = types.Mac.broadcast,
            .typ = typ,
        };
    }
};

fn addIpv4(builder: *message.Builder, code: u8, addr: types.Ipv4) message.Error!void {
    try builder.addIpv4(code, addr);
}

fn leaseMs(seconds: u32) i64 {
    return @as(i64, seconds) * 1000;
}

fn broadcastAddress(prefix: types.Prefix4) types.Ipv4 {
    return .{ .value = prefix.network().value | ~prefix.mask() };
}

const testing = std.testing;
const test_port: types.PortId = .{ .value = 1 };
const client_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 2 } };

fn testConfig() Config {
    return .{
        .port = test_port,
        .server_ip = .{ .value = 0x0a000101 },
        .prefix = types.Prefix4.parse("10.0.1.1/24") catch unreachable,
        .pool = types.parseIpRange("10.0.1.100-10.0.1.102") catch unreachable,
        .lease_seconds = 3600,
        .dns = .{ .value = 0x0a000101 },
    };
}

fn buildRequest(
    buf: []u8,
    typ: message.MessageType,
    xid: u32,
    mac: types.Mac,
    requested: ?types.Ipv4,
    server_id: ?types.Ipv4,
) ![]u8 {
    var builder = try message.Builder.init(buf, message.op_request, typ, xid, mac, 0x8000);
    if (requested) |ip| try builder.addIpv4(50, ip);
    if (server_id) |ip| try builder.addIpv4(54, ip);
    return builder.finish();
}

test "discover, request and ack allocate and bind a lease" {
    var server = try Server.init(testing.allocator, testConfig());
    defer server.deinit();

    var req_buf: [512]u8 = undefined;
    const discover = try buildRequest(&req_buf, .discover, 1, client_mac, null, null);
    var out: [512]u8 = undefined;
    const offer = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    const offered = try message.Message.parse(offer.payload);
    try testing.expectEqual(message.MessageType.offer, offered.messageType().?);
    try testing.expectEqual(@as(u32, 0x0a000164), offered.yiaddr.value);
    try testing.expectEqual(@as(u32, 0x0a000101), offered.options.serverId().?.value);
    try testing.expectEqual(
        @as(u32, 0xffffff00),
        std.mem.readInt(u32, offered.options.get(1).?[0..4], .big),
    );
    try testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, offered.options.get(51).?[0..4], .big));

    const wanted: types.Ipv4 = .{ .value = 0x0a000164 };
    const req = try buildRequest(&req_buf, .request, 1, client_mac, wanted, .{ .value = 0x0a000101 });
    const ack = (try server.handle(try message.Message.parse(req), &out, 2_000)).?;
    const acked = try message.Message.parse(ack.payload);
    try testing.expectEqual(message.MessageType.ack, acked.messageType().?);
    try testing.expectEqual(wanted.value, acked.yiaddr.value);
    try testing.expectEqual(@as(usize, 1), server.leaseCount(.bound));
}

test "pool exhaustion and conflicting requests are rejected" {
    var server = try Server.init(testing.allocator, testConfig());
    defer server.deinit();

    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    for (0..3) |i| {
        var mac = client_mac;
        mac.bytes[5] = @intCast(i + 2);
        const discover = try buildRequest(&req_buf, .discover, @intCast(i + 1), mac, null, null);
        _ = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    }

    var mac = client_mac;
    mac.bytes[5] = 9;
    const discover = try buildRequest(&req_buf, .discover, 9, mac, null, null);
    try testing.expect((try server.handle(try message.Message.parse(discover), &out, 1_000)) == null);

    const conflict = try buildRequest(
        &req_buf,
        .request,
        10,
        mac,
        .{ .value = 0x0a000164 },
        .{ .value = 0x0a000101 },
    );
    const nak = (try server.handle(try message.Message.parse(conflict), &out, 1_000)).?;
    try testing.expectEqual(message.MessageType.nak, (try message.Message.parse(nak.payload)).messageType().?);
}

test "decline quarantines an address and release frees it" {
    var server = try Server.init(testing.allocator, testConfig());
    defer server.deinit();

    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const discover = try buildRequest(&req_buf, .discover, 1, client_mac, null, null);
    const offer = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    const ip = (try message.Message.parse(offer.payload)).yiaddr;

    const decline = try buildRequest(&req_buf, .decline, 1, client_mac, ip, null);
    try testing.expect((try server.handle(try message.Message.parse(decline), &out, 1_000)) == null);
    try testing.expectEqual(@as(usize, 1), server.leaseCount(.declined));

    var other_mac = client_mac;
    other_mac.bytes[5] = 7;
    const next = try buildRequest(&req_buf, .discover, 2, other_mac, null, null);
    const next_offer = (try server.handle(try message.Message.parse(next), &out, 1_000)).?;
    try testing.expect(!(try message.Message.parse(next_offer.payload)).yiaddr.eql(ip));

    const req = try buildRequest(&req_buf, .request, 2, other_mac, (try message.Message.parse(next_offer.payload)).yiaddr, null);
    _ = (try server.handle(try message.Message.parse(req), &out, 1_000)).?;
    const release = try buildRequest(&req_buf, .release, 2, other_mac, (try message.Message.parse(next_offer.payload)).yiaddr, null);
    try testing.expect((try server.handle(try message.Message.parse(release), &out, 1_000)) == null);
    try testing.expectEqual(@as(usize, 0), server.leaseCount(.bound));
}

test "offer expiry returns the address to the pool" {
    var server = try Server.init(testing.allocator, testConfig());
    defer server.deinit();

    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const discover = try buildRequest(&req_buf, .discover, 1, client_mac, null, null);
    _ = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    try testing.expectEqual(@as(usize, 1), server.leaseCount(.offered));

    server.gc(1_000 + offer_timeout_ms);
    try testing.expectEqual(@as(usize, 0), server.leaseCount(.offered));
}

test "reservations are offered before dynamic leases and options are included" {
    var cfg = testConfig();
    cfg.domain = "lan.example";
    cfg.mtu = 1400;
    cfg.ntp = .{ .value = 0x0a000101 };
    cfg.reservations = &.{
        .{ .mac = client_mac, .ip = .{ .value = 0x0a0001c8 } },
    };

    var server = try Server.init(testing.allocator, cfg);
    defer server.deinit();

    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const discover = try buildRequest(&req_buf, .discover, 1, client_mac, null, null);
    const offer = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    const parsed = try message.Message.parse(offer.payload);
    try testing.expectEqual(@as(u32, 0x0a0001c8), parsed.yiaddr.value);
    try testing.expectEqualStrings("lan.example", parsed.options.get(15).?);
    try testing.expectEqual(@as(u16, 1400), std.mem.readInt(u16, parsed.options.get(26).?[0..2], .big));
    try testing.expectEqual(@as(u32, 0x0a000101), std.mem.readInt(u32, parsed.options.get(42).?[0..4], .big));

    var other_mac = client_mac;
    other_mac.bytes[5] = 8;
    const other = try buildRequest(&req_buf, .discover, 2, other_mac, null, null);
    const other_offer = (try server.handle(try message.Message.parse(other), &out, 1_000)).?;
    try testing.expectEqual(@as(u32, 0x0a000164), (try message.Message.parse(other_offer.payload)).yiaddr.value);
}

test "dynamic leases skip reserved addresses" {
    var cfg = testConfig();
    cfg.reservations = &.{
        .{ .mac = client_mac, .ip = .{ .value = 0x0a000164 } },
    };

    var server = try Server.init(testing.allocator, cfg);
    defer server.deinit();

    var other_mac = client_mac;
    other_mac.bytes[5] = 9;
    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const discover = try buildRequest(&req_buf, .discover, 1, other_mac, null, null);
    const offer = (try server.handle(try message.Message.parse(discover), &out, 1_000)).?;
    try testing.expectEqual(@as(u32, 0x0a000165), (try message.Message.parse(offer.payload)).yiaddr.value);

    const conflict = try buildRequest(
        &req_buf,
        .request,
        2,
        other_mac,
        .{ .value = 0x0a000164 },
        .{ .value = 0x0a000101 },
    );
    const nak = (try server.handle(try message.Message.parse(conflict), &out, 1_000)).?;
    try testing.expectEqual(message.MessageType.nak, (try message.Message.parse(nak.payload)).messageType().?);
}
