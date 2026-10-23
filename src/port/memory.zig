//! In-memory port used by tests and as a reference implementation.
//!
//! `inject` queues a frame for the datapath to read; `takeSent` pops a frame
//! written by the datapath. Both copy, so callers own their buffers.

const std = @import("std");
const types = @import("../types.zig");
const port_mod = @import("port.zig");
const PortError = @import("../errors.zig").PortError;

pub const MemoryPort = struct {
    gpa: std.mem.Allocator,
    id: types.PortId,
    name: []const u8,
    mtu: u16,
    kind: port_mod.PortKind = .memory,
    mac: types.Mac = .{},
    link_up: bool = true,
    closed: bool = false,
    max_rx: usize = 64,
    max_tx: usize = 64,
    rx: std.ArrayListUnmanaged([]u8) = .empty,
    tx: std.ArrayListUnmanaged([]u8) = .empty,
    stats: port_mod.Stats = .{},

    pub fn init(gpa: std.mem.Allocator, id: types.PortId, name: []const u8, mtu: u16) MemoryPort {
        return .{
            .gpa = gpa,
            .id = id,
            .name = name,
            .mtu = mtu,
        };
    }

    pub fn port(self: *MemoryPort) port_mod.Port {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Test helper: enqueue a frame as if it arrived from the wire.
    pub fn inject(self: *MemoryPort, frame: []const u8) PortError!void {
        if (self.closed) return error.Closed;
        if (frame.len > self.mtu) return error.FrameTooLarge;
        if (self.rx.items.len >= self.max_rx) return error.QueueFull;

        const copy = self.gpa.dupe(u8, frame) catch return error.OutOfMemory;
        errdefer self.gpa.free(copy);
        try self.rx.append(self.gpa, copy);
    }

    /// Test helper: pop the oldest frame written by the datapath.
    pub fn takeSent(self: *MemoryPort, buf: []u8) PortError!?usize {
        if (self.tx.items.len == 0) return null;
        const frame = self.tx.items[0];
        if (frame.len > buf.len) return error.FrameTooLarge;

        const n = frame.len;
        @memcpy(buf[0..n], frame);
        self.gpa.free(frame);
        _ = self.tx.orderedRemove(0);
        return n;
    }

    pub fn queuedRx(self: *const MemoryPort) usize {
        return self.rx.items.len;
    }

    pub fn queuedTx(self: *const MemoryPort) usize {
        return self.tx.items.len;
    }

    pub fn deinit(self: *MemoryPort) void {
        self.closeImpl();
    }

    fn readImpl(self: *MemoryPort, buf: []u8) PortError!?usize {
        if (self.closed) return error.Closed;
        if (!self.link_up) return null;
        if (self.rx.items.len == 0) return null;

        const frame = self.rx.items[0];
        if (frame.len > buf.len) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }

        const n = frame.len;
        @memcpy(buf[0..n], frame);
        self.gpa.free(frame);
        _ = self.rx.orderedRemove(0);

        self.stats.rx_packets += 1;
        self.stats.rx_bytes += n;
        return n;
    }

    fn writeImpl(self: *MemoryPort, frame: []const u8) PortError!void {
        if (self.closed) return error.Closed;
        if (!self.link_up) return error.LinkDown;
        if (frame.len > self.mtu) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }
        if (self.tx.items.len >= self.max_tx) {
            self.stats.drops += 1;
            return error.QueueFull;
        }

        const copy = self.gpa.dupe(u8, frame) catch return error.OutOfMemory;
        errdefer self.gpa.free(copy);
        try self.tx.append(self.gpa, copy);

        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len;
    }

    fn infoImpl(self: *MemoryPort) port_mod.PortInfo {
        return .{
            .id = self.id,
            .name = self.name,
            .kind = self.kind,
            .mac = self.mac,
            .mtu = self.mtu,
            .link = if (self.link_up) .up else .down,
            .capabilities = .{
                .l2 = true,
                .l3 = true,
                .can_set_mtu = true,
            },
        };
    }

    fn statsImpl(self: *MemoryPort) port_mod.Stats {
        return self.stats;
    }

    fn refreshImpl(self: *MemoryPort) PortError!void {
        if (self.closed) return error.Closed;
    }

    fn setUpImpl(self: *MemoryPort, up: bool) PortError!void {
        if (self.closed) return error.Closed;
        self.link_up = up;
    }

    fn setMtuImpl(self: *MemoryPort, mtu: u16) PortError!void {
        if (self.closed) return error.Closed;
        if (mtu < 576 or mtu > 9000) return error.Unsupported;
        self.mtu = mtu;
    }

    fn closeImpl(self: *MemoryPort) void {
        if (self.closed) return;
        self.closed = true;
        for (self.rx.items) |frame| self.gpa.free(frame);
        for (self.tx.items) |frame| self.gpa.free(frame);
        self.rx.deinit(self.gpa);
        self.tx.deinit(self.gpa);
        self.rx = .empty;
        self.tx = .empty;
    }
};

const vtable = port_mod.Port.VTable{
    .read = vRead,
    .write = vWrite,
    .info = vInfo,
    .stats = vStats,
    .refresh = vRefresh,
    .setUp = vSetUp,
    .setMtu = vSetMtu,
    .close = vClose,
};

fn vRead(ctx: *anyopaque, io: std.Io, buf: []u8) PortError!?usize {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.readImpl(buf);
}

fn vWrite(ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.writeImpl(frame);
}

fn vInfo(ctx: *anyopaque) port_mod.PortInfo {
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.infoImpl();
}

fn vStats(ctx: *anyopaque) port_mod.Stats {
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.statsImpl();
}

fn vRefresh(ctx: *anyopaque, io: std.Io) PortError!void {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.refreshImpl();
}

fn vSetUp(ctx: *anyopaque, io: std.Io, up: bool) PortError!void {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.setUpImpl(up);
}

fn vSetMtu(ctx: *anyopaque, io: std.Io, mtu: u16) PortError!void {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    return self.setMtuImpl(mtu);
}

fn vClose(ctx: *anyopaque, io: std.Io) void {
    _ = io;
    const self: *MemoryPort = @ptrCast(@alignCast(ctx));
    self.closeImpl();
}

test "memory port inject and read" {
    var mp = MemoryPort.init(std.testing.allocator, .{ .value = 1 }, "mem0", 1500);
    defer mp.deinit();

    const frame = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try mp.inject(&frame);
    try std.testing.expectEqual(@as(usize, 1), mp.queuedRx());

    var buf: [64]u8 = undefined;
    const n = (try mp.port().read(std.testing.io, &buf)).?;
    try std.testing.expectEqualSlices(u8, &frame, buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), mp.queuedRx());

    const stats = mp.port().stats();
    try std.testing.expectEqual(@as(u64, 1), stats.rx_packets);
    try std.testing.expectEqual(@as(u64, 4), stats.rx_bytes);
}

test "memory port write and takeSent" {
    var mp = MemoryPort.init(std.testing.allocator, .{ .value = 2 }, "mem1", 1500);
    defer mp.deinit();

    const frame = [_]u8{ 1, 2, 3, 4, 5 };
    try mp.port().write(std.testing.io, &frame);
    try std.testing.expectEqual(@as(usize, 1), mp.queuedTx());

    var buf: [64]u8 = undefined;
    const n = (try mp.takeSent(&buf)).?;
    try std.testing.expectEqualSlices(u8, &frame, buf[0..n]);

    const stats = mp.port().stats();
    try std.testing.expectEqual(@as(u64, 1), stats.tx_packets);
    try std.testing.expectEqual(@as(u64, 5), stats.tx_bytes);
}

test "memory port enforces mtu and queue limits" {
    var mp = MemoryPort.init(std.testing.allocator, .{ .value = 3 }, "mem2", 4);
    defer mp.deinit();

    const big: [5]u8 = @splat(0);
    try std.testing.expectError(error.FrameTooLarge, mp.port().write(std.testing.io, &big));

    mp.max_tx = 1;
    try mp.port().write(std.testing.io, "abcd");
    try std.testing.expectError(error.QueueFull, mp.port().write(std.testing.io, "abcd"));
}

test "memory port link state gates io" {
    var mp = MemoryPort.init(std.testing.allocator, .{ .value = 4 }, "mem3", 1500);
    defer mp.deinit();

    try mp.port().setUp(std.testing.io, false);
    try std.testing.expectEqual(port_mod.LinkState.down, mp.port().info().link);
    var scratch: [1]u8 = undefined;
    try std.testing.expect((try mp.port().read(std.testing.io, &scratch)) == null);
    try std.testing.expectError(error.LinkDown, mp.port().write(std.testing.io, "x"));
}
