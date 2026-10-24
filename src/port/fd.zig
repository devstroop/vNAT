//! L3 port backed by a host-injected file descriptor (Android `VpnService`).

const std = @import("std");
const linux = std.os.linux;
const sys = @import("linux/sys.zig");
const types = @import("../types.zig");
const port_mod = @import("port.zig");
const PortError = @import("../errors.zig").PortError;

pub const FdPort = struct {
    fd: sys.fd_t,
    id: types.PortId,
    name: []const u8,
    mtu: u16,
    link_up: bool = true,
    closed: bool = false,
    stats: port_mod.Stats = .{},

    pub const Config = struct {
        fd: sys.fd_t,
        name: []const u8,
        mtu: u16 = 1380,
    };

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        id: types.PortId,
        cfg: Config,
    ) PortError!*FdPort {
        _ = io;
        if (cfg.fd < 0) return error.InvalidArgument;
        try sys.validateName(cfg.name);

        const self = gpa.create(FdPort) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);

        const duplicated = try sys.checkFd(linux.fcntl(cfg.fd, linux.F.DUPFD_CLOEXEC, 0));
        errdefer sys.close(duplicated);

        const flags_rc = linux.fcntl(duplicated, linux.F.GETFL, 0);
        const flags_err = std.posix.errno(flags_rc);
        if (flags_err != .SUCCESS) return sys.mapErr(flags_err);
        const nonblock: u32 = 1 << @bitOffsetOf(linux.O, "NONBLOCK");
        const flags: u32 = @intCast(flags_rc);
        try sys.check(linux.fcntl(duplicated, linux.F.SETFL, @intCast(flags | nonblock)));

        self.* = .{
            .fd = duplicated,
            .id = id,
            .name = cfg.name,
            .mtu = cfg.mtu,
        };
        return self;
    }

    pub fn port(self: *FdPort) port_mod.Port {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn readImpl(self: *FdPort, buf: []u8) PortError!?usize {
        if (self.closed) return error.Closed;
        if (!self.link_up) return null;

        const n = try sys.read(self.fd, buf);
        if (n) |len| {
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += len;
            return len;
        }
        return null;
    }

    fn writeImpl(self: *FdPort, frame: []const u8) PortError!void {
        if (self.closed) return error.Closed;
        if (!self.link_up) return error.LinkDown;
        if (frame.len > self.mtu) return error.FrameTooLarge;

        try sys.write(self.fd, frame);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len;
    }

    fn infoImpl(self: *FdPort) port_mod.PortInfo {
        return .{
            .id = self.id,
            .name = self.name,
            .kind = .tun,
            .mtu = self.mtu,
            .link = if (self.link_up) .up else .down,
            .capabilities = .{ .l3 = true },
        };
    }

    fn statsImpl(self: *FdPort) port_mod.Stats {
        return self.stats;
    }

    fn refreshImpl(self: *FdPort) PortError!void {
        if (self.closed) return error.Closed;
    }

    fn setUpImpl(self: *FdPort, up: bool) PortError!void {
        if (self.closed) return error.Closed;
        self.link_up = up;
    }

    fn setMtuImpl(self: *FdPort, mtu: u16) PortError!void {
        if (self.closed) return error.Closed;
        self.mtu = mtu;
    }

    fn closeImpl(self: *FdPort) void {
        if (self.closed) return;
        sys.close(self.fd);
        self.closed = true;
    }
};

const vtable: port_mod.Port.VTable = .{
    .read = readImpl,
    .write = writeImpl,
    .info = infoImpl,
    .stats = statsImpl,
    .refresh = refreshImpl,
    .setUp = setUpImpl,
    .setMtu = setMtuImpl,
    .close = closeImpl,
};

fn readImpl(ctx: *anyopaque, _: std.Io, buf: []u8) PortError!?usize {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).readImpl(buf);
}

fn writeImpl(ctx: *anyopaque, _: std.Io, frame: []const u8) PortError!void {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).writeImpl(frame);
}

fn infoImpl(ctx: *anyopaque) port_mod.PortInfo {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).infoImpl();
}

fn statsImpl(ctx: *anyopaque) port_mod.Stats {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).statsImpl();
}

fn refreshImpl(ctx: *anyopaque, _: std.Io) PortError!void {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).refreshImpl();
}

fn setUpImpl(ctx: *anyopaque, _: std.Io, up: bool) PortError!void {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).setUpImpl(up);
}

fn setMtuImpl(ctx: *anyopaque, _: std.Io, mtu: u16) PortError!void {
    return @as(*FdPort, @ptrCast(@alignCast(ctx))).setMtuImpl(mtu);
}

fn closeImpl(ctx: *anyopaque, _: std.Io) void {
    @as(*FdPort, @ptrCast(@alignCast(ctx))).closeImpl();
}

test "fd port duplicates and pumps packets" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fds: [2]i32 = undefined;
    try sys.check(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer sys.close(fds[1]);

    var p = try FdPort.open(arena.allocator(), io, .{ .value = 7 }, .{
        .fd = fds[0],
        .name = "vpn0",
        .mtu = 1380,
    });
    sys.close(fds[0]);
    defer p.port().deinit(io);

    try sys.write(fds[1], "hello");
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, 5), try p.port().read(io, &buf));
    try std.testing.expectEqualStrings("hello", buf[0..5]);

    try p.port().write(io, "world");
    var reply: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, 5), try sys.read(fds[1], &reply));
    try std.testing.expectEqualStrings("world", reply[0..5]);

    const info = p.port().info();
    try std.testing.expectEqualStrings("vpn0", info.name);
    try std.testing.expectEqual(port_mod.PortKind.tun, info.kind);
    try std.testing.expect(info.capabilities.l3);
    try std.testing.expectEqual(@as(u16, 1380), info.mtu);
}
