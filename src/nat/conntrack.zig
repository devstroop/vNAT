//! Userspace connection tracking. One table holds both directions of a flow;
//! lookups return a pointer valid until the next insert or GC.
//!
//! R3 uses a single shard and a full sweep every second. The API keeps the
//! sharding/epoch decision out of the datapath so it can be added without
//! changing callers.

const std = @import("std");
const types = @import("../types.zig");

pub const tcp_syn_ms: i64 = 10_000;
pub const tcp_established_ms: i64 = 300_000;
pub const tcp_fin_ms: i64 = 120_000;
pub const tcp_rst_ms: i64 = 10_000;
pub const udp_ms: i64 = 30_000;
pub const icmp_ms: i64 = 30_000;
pub const other_ms: i64 = 60_000;
pub const gc_interval_ms: i64 = 1_000;

pub const State = enum {
    new,
    established,
    closing,
};

pub const FlowKey = struct {
    zone: u32,
    proto: u8,
    src: types.Ipv4,
    sport: u16,
    dst: types.Ipv4,
    dport: u16,

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        return a.zone == b.zone and
            a.proto == b.proto and
            a.src.eql(b.src) and
            a.sport == b.sport and
            a.dst.eql(b.dst) and
            a.dport == b.dport;
    }
};

pub const Nat = struct {
    snat_addr: types.Ipv4,
    snat_port: u16,
};

pub const Entry = struct {
    original: FlowKey,
    reply: FlowKey,
    nat: ?Nat = null,
    state: State = .new,
    created_ms: i64,
    last_seen_ms: i64,
    timeout_ms: i64,
    packets: u64 = 0,
    bytes: u64 = 0,
    reply_packets: u64 = 0,
    reply_bytes: u64 = 0,
};

pub const Counters = struct {
    created: u64 = 0,
    removed: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    table_full: u64 = 0,
    key_conflict: u64 = 0,
    port_exhausted: u64 = 0,
    port_reused: u64 = 0,
};

pub const Error = error{
    TableFull,
    KeyConflict,
    PortExhausted,
};

pub fn pack(key: FlowKey) u192 {
    return (@as(u192, key.zone) << 136) |
        (@as(u192, key.proto) << 128) |
        (@as(u192, key.src.value) << 96) |
        (@as(u192, key.sport) << 80) |
        (@as(u192, key.dst.value) << 48) |
        @as(u192, key.dport);
}

pub fn timeoutFor(proto: u8, state: State) i64 {
    if (proto == 6) {
        return switch (state) {
            .new => tcp_syn_ms,
            .established => tcp_established_ms,
            .closing => tcp_fin_ms,
        };
    }
    if (proto == 17) return udp_ms;
    if (proto == 1) return icmp_ms;
    return other_ms;
}

pub const Conntrack = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(?Entry) = .empty,
    free: std.ArrayListUnmanaged(u32) = .empty,
    keys: std.AutoHashMapUnmanaged(u192, u32) = .empty,
    ports: std.AutoHashMapUnmanaged(u64, void) = .empty,
    max_entries: u32,
    count: u32 = 0,
    last_gc_ms: i64 = 0,
    counters: Counters = .{},

    pub fn init(gpa: std.mem.Allocator, max_entries: u32) !Conntrack {
        var self = Conntrack{
            .gpa = gpa,
            .max_entries = max_entries,
        };
        try self.entries.ensureTotalCapacity(gpa, max_entries);
        try self.free.ensureTotalCapacity(gpa, max_entries);
        try self.keys.ensureTotalCapacity(gpa, max_entries * 2);
        try self.ports.ensureTotalCapacity(gpa, max_entries);
        return self;
    }

    pub fn deinit(self: *Conntrack) void {
        self.entries.deinit(self.gpa);
        self.free.deinit(self.gpa);
        self.keys.deinit(self.gpa);
        self.ports.deinit(self.gpa);
    }

    pub fn lookup(self: *Conntrack, key: FlowKey) ?*Entry {
        const index = self.keys.get(pack(key)) orelse {
            self.counters.misses += 1;
            return null;
        };
        self.counters.hits += 1;
        return if (self.entries.items[index]) |*entry| entry else null;
    }

    pub fn create(
        self: *Conntrack,
        original: FlowKey,
        reply: FlowKey,
        nat: ?Nat,
        now_ms: i64,
        timeout_ms: i64,
    ) Error!*Entry {
        if (self.count >= self.max_entries) {
            self.counters.table_full += 1;
            return error.TableFull;
        }

        const original_packed = pack(original);
        const reply_packed = pack(reply);
        if (self.keys.contains(original_packed) or self.keys.contains(reply_packed)) {
            self.counters.key_conflict += 1;
            return error.KeyConflict;
        }

        const index: u32 = if (self.free.items.len > 0)
            self.free.pop().?
        else
            @intCast(self.entries.items.len);

        if (index == self.entries.items.len) {
            self.entries.appendAssumeCapacity(null);
        }

        self.keys.putAssumeCapacity(original_packed, index);
        self.keys.putAssumeCapacity(reply_packed, index);

        self.entries.items[index] = .{
            .original = original,
            .reply = reply,
            .nat = nat,
            .state = if (original.proto == 6) .new else .established,
            .created_ms = now_ms,
            .last_seen_ms = now_ms,
            .timeout_ms = timeout_ms,
        };
        self.count += 1;
        self.counters.created += 1;
        return &self.entries.items[index].?;
    }

    pub fn touch(self: *Conntrack, entry: *Entry, now_ms: i64, timeout_ms: i64) void {
        _ = self;
        entry.last_seen_ms = now_ms;
        entry.timeout_ms = timeout_ms;
    }

    pub fn gc(self: *Conntrack, now_ms: i64) void {
        self.last_gc_ms = now_ms;
        var index: usize = 0;
        while (index < self.entries.items.len) : (index += 1) {
            const entry = if (self.entries.items[index]) |*value| value else continue;
            if (now_ms - entry.last_seen_ms < entry.timeout_ms) continue;
            self.removeIndex(@intCast(index));
        }
    }

    pub fn remove(self: *Conntrack, entry: *Entry) void {
        const index = self.indexFor(entry.original) orelse return;
        self.removeIndex(index);
    }

    /// Preserves `preferred` when free, otherwise allocates deterministically
    /// from 1024..65535 for this (protocol, address).
    pub fn allocPort(
        self: *Conntrack,
        proto: u8,
        addr: types.Ipv4,
        preferred: u16,
    ) Error!u16 {
        if (preferred >= 1024 and !self.ports.contains(portKey(proto, addr, preferred))) {
            self.ports.putAssumeCapacity(portKey(proto, addr, preferred), {});
            self.counters.port_reused += 1;
            return preferred;
        }

        const span: u32 = 65535 - 1024 + 1;
        const seed = portKey(proto, addr, preferred);
        const offset: u32 = @truncate(std.hash.Wyhash.hash(0, std.mem.asBytes(&seed)) % span);
        var probe: u32 = 0;
        while (probe < span) : (probe += 1) {
            const candidate: u16 = @intCast(1024 + ((offset + probe) % span));
            if (!self.ports.contains(portKey(proto, addr, candidate))) {
                self.ports.putAssumeCapacity(portKey(proto, addr, candidate), {});
                return candidate;
            }
        }

        self.counters.port_exhausted += 1;
        return error.PortExhausted;
    }

    pub fn freePort(self: *Conntrack, proto: u8, addr: types.Ipv4, port: u16) void {
        _ = self.ports.remove(portKey(proto, addr, port));
    }

    fn indexFor(self: *Conntrack, key: FlowKey) ?u32 {
        return self.keys.get(pack(key));
    }

    fn removeIndex(self: *Conntrack, index: u32) void {
        const entry = if (self.entries.items[index]) |*value| value else return;
        _ = self.keys.remove(pack(entry.original));
        _ = self.keys.remove(pack(entry.reply));
        if (entry.nat) |nat| self.freePort(entry.original.proto, nat.snat_addr, nat.snat_port);
        self.entries.items[index] = null;
        self.free.appendAssumeCapacity(index);
        self.count -= 1;
        self.counters.removed += 1;
    }
};

fn portKey(proto: u8, addr: types.Ipv4, port: u16) u64 {
    return (@as(u64, proto) << 48) |
        (@as(u64, addr.value) << 16) |
        @as(u64, port);
}

const testing = std.testing;

fn testIp(s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

fn tcpKey(src: []const u8, sport: u16, dst: []const u8, dport: u16) FlowKey {
    return .{
        .zone = 1,
        .proto = 6,
        .src = testIp(src),
        .sport = sport,
        .dst = testIp(dst),
        .dport = dport,
    };
}

test "tracks both directions and expires" {
    var ct = try Conntrack.init(testing.allocator, 8);
    defer ct.deinit();

    const original = tcpKey("10.0.1.2", 40000, "10.0.2.2", 80);
    const reply = tcpKey("10.0.2.2", 80, "10.0.2.1", 40000);
    _ = try ct.create(original, reply, .{
        .snat_addr = testIp("10.0.2.1"),
        .snat_port = 40000,
    }, 1_000, tcp_established_ms);

    try testing.expect(ct.lookup(original) != null);
    try testing.expect(ct.lookup(reply) != null);
    try testing.expectEqual(@as(u32, 1), ct.count);

    ct.gc(1_000 + tcp_established_ms - 1);
    try testing.expectEqual(@as(u32, 1), ct.count);
    ct.gc(1_000 + tcp_established_ms);
    try testing.expectEqual(@as(u32, 0), ct.count);
    try testing.expect(ct.lookup(original) == null);
    try testing.expect(!ct.ports.contains(portKey(6, testIp("10.0.2.1"), 40000)));
}

test "port allocation preserves and avoids collisions" {
    var ct = try Conntrack.init(testing.allocator, 8);
    defer ct.deinit();

    const addr = testIp("10.0.2.1");
    try testing.expectEqual(@as(u16, 40000), try ct.allocPort(6, addr, 40000));
    try testing.expectEqual(@as(u16, 40000), try ct.allocPort(17, addr, 40000));

    const second = try ct.allocPort(6, addr, 40000);
    try testing.expect(second != 40000);

    ct.freePort(6, addr, 40000);
    try testing.expectEqual(@as(u16, 40000), try ct.allocPort(6, addr, 40000));
}

test "table cap and key conflicts" {
    var ct = try Conntrack.init(testing.allocator, 2);
    defer ct.deinit();

    const a = tcpKey("10.0.1.2", 1, "10.0.2.2", 80);
    const ar = tcpKey("10.0.2.2", 80, "10.0.2.1", 1);
    _ = try ct.create(a, ar, null, 0, tcp_established_ms);

    const b = tcpKey("10.0.1.3", 1, "10.0.2.2", 80);
    const br = tcpKey("10.0.2.2", 80, "10.0.2.1", 2);
    _ = try ct.create(b, br, null, 0, tcp_established_ms);

    const c = tcpKey("10.0.1.4", 1, "10.0.2.2", 80);
    const cr = tcpKey("10.0.2.2", 80, "10.0.2.1", 3);
    try testing.expectError(error.TableFull, ct.create(c, cr, null, 0, tcp_established_ms));

    ct.gc(tcp_established_ms + 1);
    _ = try ct.create(c, cr, null, 0, tcp_established_ms);

    const d = tcpKey("10.0.1.5", 1, "10.0.2.2", 80);
    try testing.expectError(error.KeyConflict, ct.create(d, c, null, 0, tcp_established_ms));
}

test "timeout defaults" {
    try testing.expectEqual(tcp_syn_ms, timeoutFor(6, .new));
    try testing.expectEqual(tcp_established_ms, timeoutFor(6, .established));
    try testing.expectEqual(tcp_fin_ms, timeoutFor(6, .closing));
    try testing.expectEqual(udp_ms, timeoutFor(17, .established));
    try testing.expectEqual(icmp_ms, timeoutFor(1, .established));
    try testing.expectEqual(other_ms, timeoutFor(47, .established));
}

test "zone separates otherwise identical tuples" {
    var ct = try Conntrack.init(testing.allocator, 4);
    defer ct.deinit();

    const original = tcpKey("10.0.1.2", 40000, "10.0.2.2", 80);
    var reply = tcpKey("10.0.2.2", 80, "10.0.2.1", 40000);
    reply.zone = 2;
    _ = try ct.create(original, reply, null, 0, tcp_established_ms);

    try testing.expect(ct.lookup(original) != null);
    try testing.expect(ct.lookup(reply) != null);

    var wrong = original;
    wrong.zone = 2;
    try testing.expect(ct.lookup(wrong) == null);
}
