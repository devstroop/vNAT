//! TUN/TAP ports.
//!
//! The device is created with `TUNSETIFF` and always uses `IFF_NO_PI`, so the
//! fd carries raw IP packets (TUN) or Ethernet frames (TAP). The fd is
//! non-blocking; reads return null when no packet is ready.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");
const iface = @import("iface.zig");
const types = @import("../../types.zig");
const port_mod = @import("../port.zig");
const PortError = @import("../../errors.zig").PortError;

const TUNSETIFF: u32 = 0x400454ca;
const IFF_TUN: u16 = 0x0001;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;

pub const TunPort = struct {
    fd: sys.fd_t,
    id: types.PortId,
    kind: port_mod.PortKind,
    name_buf: [sys.IFNAMESIZE]u8 = @splat(0),
    name_len: u8 = 0,
    ifindex: u32 = 0,
    mtu: u16 = 1500,
    mac: types.Mac = .{},
    link_up: bool = false,
    closed: bool = false,
    stats: port_mod.Stats = .{},

    pub const Config = struct {
        name: []const u8,
        tap: bool,
        mtu: ?u16 = null,
    };

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        id: types.PortId,
        cfg: Config,
    ) PortError!*TunPort {
        _ = io;
        try sys.validateName(cfg.name);

        const self = gpa.create(TunPort) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);

        const fd = try sys.checkFd(linux.openat(
            linux.AT.FDCWD,
            "/dev/net/tun",
            .{
                .ACCMODE = .RDWR,
                .NONBLOCK = true,
                .CLOEXEC = true,
            },
            0,
        ));
        errdefer sys.close(fd);

        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        @memcpy(ifr.ifrn.name[0..cfg.name.len], cfg.name);
        const flags: u16 = (if (cfg.tap) IFF_TAP else IFF_TUN) | IFF_NO_PI;
        ifr.ifru.flags = @bitCast(flags);
        try sys.ioctl(fd, TUNSETIFF, &ifr);

        const actual = std.mem.sliceTo(ifr.ifrn.name[0..], 0);
        if (actual.len == 0 or actual.len >= sys.IFNAMESIZE) return error.Io;

        const ifindex = try iface.ifindex(actual);
        const mtu = try iface.mtu(actual);
        const mac = iface.mac(actual) catch types.Mac{};
        const link_up = iface.isUp(actual) catch false;

        if (cfg.mtu) |requested| {
            try iface.setMtu(actual, requested);
        }

        self.* = .{
            .fd = fd,
            .id = id,
            .kind = if (cfg.tap) .tap else .tun,
            .name_len = @intCast(actual.len),
            .ifindex = ifindex,
            .mtu = cfg.mtu orelse mtu,
            .mac = mac,
            .link_up = link_up,
        };
        @memcpy(self.name_buf[0..actual.len], actual);
        return self;
    }

    pub fn port(self: *TunPort) port_mod.Port {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn name(self: *const TunPort) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    fn readImpl(self: *TunPort, buf: []u8) PortError!?usize {
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

    fn writeImpl(self: *TunPort, frame: []const u8) PortError!void {
        if (self.closed) return error.Closed;
        if (!self.link_up) return error.LinkDown;

        try sys.write(self.fd, frame);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len;
    }

    fn infoImpl(self: *TunPort) port_mod.PortInfo {
        return .{
            .id = self.id,
            .name = self.name(),
            .ifindex = self.ifindex,
            .kind = self.kind,
            .mac = self.mac,
            .mtu = self.mtu,
            .link = if (self.link_up) .up else .down,
            .capabilities = .{
                .l2 = self.kind == .tap,
                .l3 = self.kind == .tun,
                .can_set_mtu = true,
            },
        };
    }

    fn statsImpl(self: *TunPort) port_mod.Stats {
        return self.stats;
    }

    fn refreshImpl(self: *TunPort) PortError!void {
        if (self.closed) return error.Closed;
        const ifname = self.name();

        const ifindex = iface.ifindex(ifname) catch |err| switch (err) {
            error.NotFound => {
                self.link_up = false;
                return;
            },
            else => return err,
        };
        self.ifindex = ifindex;
        self.mtu = iface.mtu(ifname) catch self.mtu;
        self.mac = iface.mac(ifname) catch self.mac;
        self.link_up = iface.isUp(ifname) catch false;
    }

    fn setUpImpl(self: *TunPort, up: bool) PortError!void {
        if (self.closed) return error.Closed;
        try iface.setUp(self.name(), up);
        self.link_up = up;
    }

    fn setMtuImpl(self: *TunPort, mtu: u16) PortError!void {
        if (self.closed) return error.Closed;
        try iface.setMtu(self.name(), mtu);
        self.mtu = mtu;
    }

    fn closeImpl(self: *TunPort) void {
        if (self.closed) return;
        sys.close(self.fd);
        self.closed = true;
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
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.readImpl(buf);
}

fn vWrite(ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void {
    _ = io;
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.writeImpl(frame);
}

fn vInfo(ctx: *anyopaque) port_mod.PortInfo {
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.infoImpl();
}

fn vStats(ctx: *anyopaque) port_mod.Stats {
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.statsImpl();
}

fn vRefresh(ctx: *anyopaque, io: std.Io) PortError!void {
    _ = io;
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.refreshImpl();
}

fn vSetUp(ctx: *anyopaque, io: std.Io, up: bool) PortError!void {
    _ = io;
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.setUpImpl(up);
}

fn vSetMtu(ctx: *anyopaque, io: std.Io, mtu: u16) PortError!void {
    _ = io;
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    return self.setMtuImpl(mtu);
}

fn vClose(ctx: *anyopaque, io: std.Io) void {
    _ = io;
    const self: *TunPort = @ptrCast(@alignCast(ctx));
    self.closeImpl();
}
