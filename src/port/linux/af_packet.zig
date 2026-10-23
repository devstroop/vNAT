//! AF_PACKET L2 ports.
//!
//! One raw socket per interface, bound to `ETH_P_ALL`. `PACKET_IGNORE_OUTGOING`
//! prevents the datapath from reading frames it just transmitted,
//! `PACKET_MR_PROMISC` is enabled so a userspace bridge sees unicast frames
//! addressed to other hosts, and `PACKET_AUXDATA` recovers 802.1Q tags that
//! VLAN offload stripped before the frame reached the packet socket.

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
const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

const TpacketAuxdata = extern struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
};

const PacketMreq = extern struct {
    ifindex: i32,
    type: u16,
    alen: u16,
    address: [8]u8 = @splat(0),
};

pub const AfPacketPort = struct {
    fd: sys.fd_t,
    id: types.PortId,
    ifindex: u32,
    name_buf: [sys.IFNAMESIZE]u8 = @splat(0),
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
            var iov = [1]std.posix.iovec{.{
                .base = buf.ptr,
                .len = buf.len,
            }};
            var control: [128]u8 align(@alignOf(usize)) = undefined;
            var msg: linux.msghdr = .{
                .name = @ptrCast(&src),
                .namelen = @sizeOf(@TypeOf(src)),
                .iov = &iov,
                .iovlen = 1,
                .control = &control,
                .controllen = control.len,
                .flags = 0,
            };
            const rc = linux.recvmsg(self.fd, &msg, 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return null;
                    if (src.pkttype == linux.PACKET.OUTGOING) {
                        // Fallback for kernels without PACKET_IGNORE_OUTGOING.
                        self.stats.drops += 1;
                        continue;
                    }
                    var len: usize = rc;
                    if (auxVlanTci(control[0..msg.controllen])) |tci| {
                        len = restoreVlan(buf, len, tci) orelse {
                            self.stats.drops += 1;
                            continue;
                        };
                    }
                    self.stats.rx_packets += 1;
                    self.stats.rx_bytes += len;
                    return len;
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
        .addr = @splat(0),
    };
    try sys.check(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));

    if (ignore_outgoing) setIgnoreOutgoing(fd);
    try setAuxdata(fd);
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

fn setAuxdata(fd: sys.fd_t) PortError!void {
    var one: u32 = 1;
    try sys.check(linux.setsockopt(
        fd,
        SOL_PACKET,
        linux.PACKET.AUXDATA,
        std.mem.asBytes(&one).ptr,
        @sizeOf(u32),
    ));
}

fn auxVlanTci(control: []const u8) ?u16 {
    var off: usize = 0;
    while (off + @sizeOf(linux.cmsghdr) <= control.len) {
        const hdr = @as(*align(1) const linux.cmsghdr, @ptrCast(control[off..].ptr));
        if (hdr.len < @sizeOf(linux.cmsghdr)) return null;
        if (hdr.level == SOL_PACKET and hdr.type == linux.PACKET.AUXDATA) {
            const data_off = off + cmsgAlign(@sizeOf(linux.cmsghdr));
            const data_end = @min(control.len, off + hdr.len);
            if (data_off + @sizeOf(TpacketAuxdata) <= data_end) {
                const aux = @as(*align(1) const TpacketAuxdata, @ptrCast(control[data_off..].ptr));
                if (aux.tp_status & TP_STATUS_VLAN_VALID == 0) return null;
                if (aux.tp_status & TP_STATUS_VLAN_TPID_VALID != 0 and
                    aux.tp_vlan_tpid != 0x8100)
                {
                    return null;
                }
                return aux.tp_vlan_tci & 0x0fff;
            }
        }
        off += cmsgAlign(hdr.len);
    }
    return null;
}

fn cmsgAlign(len: usize) usize {
    const align_size: usize = @sizeOf(usize);
    return (len + align_size - 1) & ~(align_size - 1);
}

/// VLAN offload can remove the 802.1Q header and report the TCI through
/// PACKET_AUXDATA. Reinsert it so the datapath sees one canonical frame format.
fn restoreVlan(buf: []u8, len: usize, tci: u16) ?usize {
    if (len < 14) return len;
    if ((@as(u16, buf[12]) << 8) | buf[13] == 0x8100) return len;
    if (len + 4 > buf.len) return null;
    std.mem.copyBackwards(u8, buf[16 .. len + 4], buf[12..len]);
    buf[12] = 0x81;
    buf[13] = 0x00;
    buf[14] = @truncate(tci >> 8);
    buf[15] = @truncate(tci);
    return len + 4;
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

const testing = std.testing;

test "restoreVlan inserts an offloaded 802.1q tag" {
    var buf: [64]u8 = undefined;
    @memset(buf[0..22], 0);
    buf[12] = 0x08;
    buf[13] = 0x00;
    @memcpy(buf[14..18], "data");
    const out = restoreVlan(&buf, 18, 0x2064).?;
    try testing.expectEqual(@as(usize, 22), out);
    try testing.expectEqual(@as(u8, 0x81), buf[12]);
    try testing.expectEqual(@as(u8, 0x00), buf[13]);
    try testing.expectEqual(@as(u8, 0x20), buf[14]);
    try testing.expectEqual(@as(u8, 0x64), buf[15]);
    try testing.expectEqual(@as(u8, 0x08), buf[16]);
    try testing.expectEqual(@as(u8, 0x00), buf[17]);
    try testing.expectEqualSlices(u8, "data", buf[18..22]);
}

test "restoreVlan keeps an existing tag" {
    var buf: [64]u8 = undefined;
    @memset(buf[0..22], 0);
    buf[12] = 0x81;
    buf[13] = 0x00;
    const out = restoreVlan(&buf, 22, 10).?;
    try testing.expectEqual(@as(usize, 22), out);
}

test "restoreVlan reports a full buffer" {
    var buf: [18]u8 = undefined;
    @memset(&buf, 0);
    try testing.expectEqual(@as(?usize, null), restoreVlan(&buf, 18, 10));
}

test "auxVlanTci reads a valid auxdata cmsg" {
    var control: [128]u8 align(@alignOf(usize)) = @splat(0);
    const hdr = @as(*align(1) linux.cmsghdr, @ptrCast(&control));
    hdr.level = SOL_PACKET;
    hdr.type = linux.PACKET.AUXDATA;
    const data_off = cmsgAlign(@sizeOf(linux.cmsghdr));
    const aux = @as(*align(1) TpacketAuxdata, @ptrCast(control[data_off..].ptr));
    aux.* = .{
        .tp_status = TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID,
        .tp_len = 0,
        .tp_snaplen = 0,
        .tp_mac = 0,
        .tp_net = 0,
        .tp_vlan_tci = 0x2064,
        .tp_vlan_tpid = 0x8100,
    };
    hdr.len = data_off + @sizeOf(TpacketAuxdata);
    try testing.expectEqual(@as(?u16, 0x64), auxVlanTci(control[0..hdr.len]));
}

test "auxVlanTci ignores absent or foreign tags" {
    var control: [128]u8 align(@alignOf(usize)) = @splat(0);
    const hdr = @as(*align(1) linux.cmsghdr, @ptrCast(&control));
    hdr.level = SOL_PACKET;
    hdr.type = linux.PACKET.AUXDATA;
    const data_off = cmsgAlign(@sizeOf(linux.cmsghdr));
    const aux = @as(*align(1) TpacketAuxdata, @ptrCast(control[data_off..].ptr));
    aux.* = .{
        .tp_status = TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID,
        .tp_len = 0,
        .tp_snaplen = 0,
        .tp_mac = 0,
        .tp_net = 0,
        .tp_vlan_tci = 10,
        .tp_vlan_tpid = 0x88a8,
    };
    hdr.len = data_off + @sizeOf(TpacketAuxdata);
    try testing.expectEqual(@as(?u16, null), auxVlanTci(control[0..hdr.len]));

    aux.tp_status = 0;
    try testing.expectEqual(@as(?u16, null), auxVlanTci(control[0..hdr.len]));
}
