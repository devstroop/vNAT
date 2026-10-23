//! AF_PACKET L2 ports.
//!
//! One raw socket per interface, bound to `ETH_P_ALL`. `PACKET_IGNORE_OUTGOING`
//! prevents the datapath from reading frames it just transmitted, and
//! `PACKET_MR_PROMISC` is enabled so a userspace bridge sees unicast frames
//! addressed to other hosts.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");
const iface = @import("iface.zig");
const types = @import("../../types.zig");
const port_mod = @import("../port.zig");
const PortError = @import("../../errors.zig").PortError;

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: i32 = 263;
const PACKET_IGNORE_OUTGOING: u32 = 23;
const PACKET_MR_PROMISC: u16 = 1;

const PacketMreq = extern struct {
    ifindex: i32,
    type: u16,
    alen: u16,
    address: [8]u8 = [_]u8{0} ** 8,
};

pub const AfPacketPort = struct {
    fd: sys.fd_t,
    id: types.PortId,
    ifindex: u32,
    name_buf: [sys.IFNAMESIZE]u8 = [_]u8{0} ** sys.IFNAMESIZE,
    name_len: u8 = 0,
    mtu: u16 = 1500,
    mac: types.Mac = .{},
    link_up: bool = false,
    promiscuous: bool = false,
    ignore_outgoing: bool = true,
    closed: bool = false,
    stats: port_mod.Stats = .{},

    pub const Config = struct {
        name: []const u8,
        promiscuous: bool = true,
        ignore_outgoing: bool = true,
    };

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        id: types.PortId,
        cfg: Config,
    ) PortError!*AfPacketPort {
        _ = io;
        try sys.validateName(cfg.name);

        const ifindex = try iface.ifindex(cfg.name);

        const self = gpa.create(AfPacketPort) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);

        const fd = try openSocket(ifindex, cfg.promiscuous, cfg.ignore_outgoing);
        errdefer sys.close(fd);

        self.* = .{
            .fd = fd,
            .id = id,
            .ifindex = ifindex,
            .name_len = @intCast(cfg.name.len),
            .mtu = iface.mtu(cfg.name) catch 1500,
            .mac = iface.mac(cfg.name) catch types.Mac{},
            .link_up = iface.isUp(cfg.name) catch false,
            .promiscuous = cfg.promiscuous,
            .ignore_outgoing = cfg.ignore_outgoing,
        };
        @memcpy(self.name_buf[0..cfg.name.len], cfg.name);
        return self;
    }

    pub fn port(self: *AfPacketPort) port_mod.Port {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn name(self: *const AfPacketPort) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    fn readImpl(self: *AfPacketPort, buf: []u8) PortError!?usize {
        if (self.closed) return error.Closed;
        if (!self.link_up) return null;

        while (true) {
            var src: linux.sockaddr.ll = std.mem.zeroes(linux.sockaddr.ll);
            var addr_len: linux.socklen_t = @sizeOf(@TypeOf(src));
            const rc = linux.recvfrom(
                self.fd,
                buf.ptr,
                buf.len,
                0,
                @ptrCast(&src),
                &addr_len,
            );
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return null;
                    if (src.pkttype == linux.PACKET.OUTGOING) {
                        // Fallback for kernels without PACKET_IGNORE_OUTGOING.
                        self.stats.drops += 1;
                        continue;
                    }
                    self.stats.rx_packets += 1;
                    self.stats.rx_bytes += rc;
                    return rc;
                },
                .AGAIN, .INTR => return null,
                else => |e| return sys.mapErr(e),
            }
        }
    }

    fn writeImpl(self: *AfPacketPort, frame: []const u8) PortError!void {
        if (self.closed) return error.Closed;
        if (!self.link_up) return error.LinkDown;

        try sys.write(self.fd, frame);
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += frame.len;
    }

    fn infoImpl(self: *AfPacketPort) port_mod.PortInfo {
        return .{
            .id = self.id,
            .name = self.name(),
            .ifindex = self.ifindex,
            .kind = .ethernet,
            .mac = self.mac,
            .mtu = self.mtu,
            .link = if (self.link_up) .up else .down,
            .capabilities = .{
                .l2 = true,
                .promiscuous = self.promiscuous,
                .multicast = true,
            },
        };
    }

    fn statsImpl(self: *AfPacketPort) port_mod.Stats {
        return self.stats;
    }

    fn refreshImpl(self: *AfPacketPort) PortError!void {
        if (self.closed) return error.Closed;
        const ifname = self.name();

        const ifindex = iface.ifindex(ifname) catch |err| switch (err) {
            error.NotFound => {
                self.link_up = false;
                return;
            },
            else => return err,
        };
        if (ifindex != self.ifindex) {
            // The interface was recreated with a new ifindex: the old socket
            // is bound to a dead index, so replace it.
            const fd = try openSocket(ifindex, self.promiscuous, self.ignore_outgoing);
            sys.close(self.fd);
            self.fd = fd;
            self.ifindex = ifindex;
        }
        self.mtu = iface.mtu(ifname) catch self.mtu;
        self.mac = iface.mac(ifname) catch self.mac;
        self.link_up = iface.isUp(ifname) catch false;
    }

    fn setUpImpl(self: *AfPacketPort, up: bool) PortError!void {
        if (self.closed) return error.Closed;
        try iface.setUp(self.name(), up);
        self.link_up = up;
    }

    fn setMtuImpl(self: *AfPacketPort, mtu: u16) PortError!void {
        if (self.closed) return error.Closed;
        try iface.setMtu(self.name(), mtu);
        self.mtu = mtu;
    }

    fn closeImpl(self: *AfPacketPort) void {
        if (self.closed) return;
        sys.close(self.fd);
        self.closed = true;
    }
};

fn openSocket(ifindex: u32, promiscuous: bool, ignore_outgoing: bool) PortError!sys.fd_t {
    const protocol = std.mem.nativeToBig(u16, ETH_P_ALL);
    const fd = try sys.checkFd(linux.socket(
        linux.AF.PACKET,
        @intCast(linux.SOCK.RAW | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
        @as(u32, protocol),
    ));
    errdefer sys.close(fd);

    var addr: linux.sockaddr.ll = .{
        .family = linux.AF.PACKET,
        .protocol = protocol,
        .ifindex = @intCast(ifindex),
        .hatype = 0,
        .pkttype = 0,
        .halen = 0,
        .addr = [_]u8{0} ** 8,
    };
    try sys.check(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));

    if (ignore_outgoing) setIgnoreOutgoing(fd);
    if (promiscuous) try setPromiscuous(fd, ifindex);
    return fd;
}

fn setIgnoreOutgoing(fd: sys.fd_t) void {
    var one: u32 = 1;
    // Kernels before 4.20 do not know this option; ignore the failure and let
    // the caller filter PACKET_OUTGOING if needed.
    _ = linux.setsockopt(
        fd,
        SOL_PACKET,
        PACKET_IGNORE_OUTGOING,
        std.mem.asBytes(&one).ptr,
        @sizeOf(u32),
    );
}

fn setPromiscuous(fd: sys.fd_t, ifindex: u32) PortError!void {
    var mreq: PacketMreq = .{
        .ifindex = @intCast(ifindex),
        .type = PACKET_MR_PROMISC,
        .alen = 0,
    };
    try sys.check(linux.setsockopt(
        fd,
        SOL_PACKET,
        linux.PACKET.ADD_MEMBERSHIP,
        std.mem.asBytes(&mreq).ptr,
        @sizeOf(PacketMreq),
    ));
}

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
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.readImpl(buf);
}

fn vWrite(ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void {
    _ = io;
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.writeImpl(frame);
}

fn vInfo(ctx: *anyopaque) port_mod.PortInfo {
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.infoImpl();
}

fn vStats(ctx: *anyopaque) port_mod.Stats {
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.statsImpl();
}

fn vRefresh(ctx: *anyopaque, io: std.Io) PortError!void {
    _ = io;
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.refreshImpl();
}

fn vSetUp(ctx: *anyopaque, io: std.Io, up: bool) PortError!void {
    _ = io;
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.setUpImpl(up);
}

fn vSetMtu(ctx: *anyopaque, io: std.Io, mtu: u16) PortError!void {
    _ = io;
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    return self.setMtuImpl(mtu);
}

fn vClose(ctx: *anyopaque, io: std.Io) void {
    _ = io;
    const self: *AfPacketPort = @ptrCast(@alignCast(ctx));
    self.closeImpl();
}
