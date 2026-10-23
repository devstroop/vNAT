//! rtnetlink: link enumeration and hotplug event monitoring.
//!
//! All message parsing is bounds-checked and operates on raw bytes. Netlink
//! numeric fields are host-endian; lengths are 4-byte aligned.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");
const iface_mod = @import("iface.zig");
const types = @import("../../types.zig");
const PortError = @import("../../errors.zig").PortError;

const native_endian = @import("builtin").cpu.arch.endian();

const NETLINK_ROUTE: u32 = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;

const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_NEIGH: u32 = 0x4;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_MASTER: u16 = 10;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_CARRIER: u16 = 33;

const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

const IFLA_BR_STP_STATE: u16 = 5;
const IFLA_BR_VLAN_FILTERING: u16 = 7;
const IFLA_BR_VLAN_DEFAULT_PVID: u16 = 39;

const IFLA_BRIDGE_FLAGS: u16 = 0;
const IFLA_BRIDGE_VLAN_INFO: u16 = 2;
const BRIDGE_VLAN_INFO_PVID: u16 = 1 << 1;
const BRIDGE_VLAN_INFO_UNTAGGED: u16 = 1 << 2;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;

const RT_TABLE_MAIN: u32 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x10000;
const IF_OPER_UP: u8 = 6;

const AF_INET: u8 = 2;
const AF_BRIDGE: u8 = 7;

const NLMSG_HDR_LEN = 16;

const NlMsgHdr = extern struct {
    len: u32,
    type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

pub const Kind = enum { link, addr, neigh };
pub const Action = enum { add, del };

pub const Event = struct {
    kind: Kind,
    action: Action,
    index: u32,
    name_buf: [sys.IFNAMESIZE]u8 = [_]u8{0} ** sys.IFNAMESIZE,
    name_len: u8 = 0,
    mtu: u16 = 0,
    mac: types.Mac = .{},
    up: bool = false,
    family: u8 = 0,
    addr: [4]u8 = [_]u8{0} ** 4,
    prefix_len: u8 = 0,

    pub fn name(self: *const Event) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const LinkInfo = struct {
    index: u32,
    name_buf: [sys.IFNAMESIZE]u8 = [_]u8{0} ** sys.IFNAMESIZE,
    name_len: u8 = 0,
    mtu: u16 = 1500,
    mac: types.Mac = .{},
    up: bool = false,
    running: bool = false,
    operstate: u8 = 0,
    master: u32 = 0,

    pub fn name(self: *const LinkInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

const LinkData = struct {
    index: u32,
    name_buf: [sys.IFNAMESIZE]u8 = [_]u8{0} ** sys.IFNAMESIZE,
    name_len: u8 = 0,
    mtu: u16 = 1500,
    mac: types.Mac = .{},
    up: bool = false,
    running: bool = false,
    operstate: u8 = 0,
    carrier: bool = false,
    master: u32 = 0,
};

// --- primitive readers ----------------------------------------------------

fn readU16(buf: []const u8, off: usize) ?u16 {
    if (off + 2 > buf.len) return null;
    return std.mem.readInt(u16, @ptrCast(buf[off..][0..2]), native_endian);
}

fn readU32(buf: []const u8, off: usize) ?u32 {
    if (off + 4 > buf.len) return null;
    return std.mem.readInt(u32, @ptrCast(buf[off..][0..4]), native_endian);
}

fn readI32(buf: []const u8, off: usize) ?i32 {
    if (off + 4 > buf.len) return null;
    return std.mem.readInt(i32, @ptrCast(buf[off..][0..4]), native_endian);
}

fn writeU16(buf: []u8, off: usize, value: u16) void {
    std.mem.writeInt(u16, @ptrCast(buf[off..][0..2]), value, native_endian);
}

fn writeU32(buf: []u8, off: usize, value: u32) void {
    std.mem.writeInt(u32, @ptrCast(buf[off..][0..4]), value, native_endian);
}

const Attr = struct {
    typ: u16,
    data: []const u8,
};

/// Iterates rtattrs in place. Returns null on a malformed attribute; the
/// caller drops the rest of the message rather than guessing.
fn nextAttr(buf: []const u8, off: *usize) ?Attr {
    if (off.* + 4 > buf.len) return null;
    const len = readU16(buf, off.*) orelse return null;
    const typ = readU16(buf, off.* + 2) orelse return null;
    if (len < 4 or off.* + len > buf.len) return null;

    const data = buf[off.* + 4 .. off.* + len];
    const padded = std.mem.alignForward(usize, @as(usize, len), 4);
    off.* = if (off.* + padded > buf.len) buf.len else off.* + padded;
    return .{ .typ = typ & 0x3fff, .data = data };
}

fn copyName(dst: *[sys.IFNAMESIZE]u8, dst_len: *u8, data: []const u8) void {
    const end = std.mem.indexOfScalar(u8, data, 0) orelse data.len;
    const len = @min(end, dst.len - 1);
    @memcpy(dst[0..len], data[0..len]);
    dst_len.* = @intCast(len);
}

// --- parsers --------------------------------------------------------------

fn parseLinkData(payload: []const u8) ?LinkData {
    if (payload.len < NLMSG_HDR_LEN) return null;

    const index = readI32(payload, 4) orelse return null;
    if (index <= 0) return null;
    const flags = readU32(payload, 8) orelse return null;

    var out = LinkData{
        .index = @intCast(index),
        .up = flags & IFF_UP != 0,
        .running = flags & IFF_RUNNING != 0,
    };

    var off: usize = NLMSG_HDR_LEN;
    while (off + 4 <= payload.len) {
        const attr = nextAttr(payload, &off) orelse break;
        switch (attr.typ) {
            IFLA_IFNAME => copyName(&out.name_buf, &out.name_len, attr.data),
            IFLA_MTU => {
                if (readU32(attr.data, 0)) |mtu| out.mtu = @intCast(@min(mtu, 65535));
            },
            IFLA_MASTER => {
                if (readU32(attr.data, 0)) |master| out.master = master;
            },
            IFLA_ADDRESS => {
                if (attr.data.len >= 6) @memcpy(&out.mac.bytes, attr.data[0..6]);
            },
            IFLA_OPERSTATE => {
                if (attr.data.len >= 1) out.operstate = attr.data[0];
            },
            IFLA_CARRIER => {
                if (attr.data.len >= 1) out.carrier = attr.data[0] != 0;
            },
            else => {},
        }
    }

    out.up = out.up and
        (out.running or out.operstate == IF_OPER_UP or out.carrier or
            flags & IFF_LOWER_UP != 0);
    return out;
}

fn parseLinkEvent(payload: []const u8, add: bool) ?Event {
    const link = parseLinkData(payload) orelse return null;
    return .{
        .kind = .link,
        .action = if (add) .add else .del,
        .index = link.index,
        .name_buf = link.name_buf,
        .name_len = link.name_len,
        .mtu = link.mtu,
        .mac = link.mac,
        .up = link.up,
    };
}

fn parseAddrEvent(payload: []const u8, add: bool) ?Event {
    if (payload.len < 8) return null;
    const family = payload[0];
    const prefix_len = payload[1];
    const index = readU32(payload, 4) orelse return null;

    var event = Event{
        .kind = .addr,
        .action = if (add) .add else .del,
        .index = index,
        .family = family,
        .prefix_len = prefix_len,
    };

    var off: usize = 8;
    while (off + 4 <= payload.len) {
        const attr = nextAttr(payload, &off) orelse break;
        if (attr.typ != IFA_ADDRESS and attr.typ != IFA_LOCAL) continue;
        if (family != AF_INET or attr.data.len < 4) continue;
        @memcpy(&event.addr, attr.data[0..4]);
        if (attr.typ == IFA_LOCAL) break;
    }
    return event;
}

fn parseNeighEvent(payload: []const u8, add: bool) ?Event {
    if (payload.len < 12) return null;
    const family = payload[0];
    const index = readU32(payload, 4) orelse return null;

    var event = Event{
        .kind = .neigh,
        .action = if (add) .add else .del,
        .index = index,
        .family = family,
    };

    var off: usize = 12;
    while (off + 4 <= payload.len) {
        const attr = nextAttr(payload, &off) orelse break;
        switch (attr.typ) {
            NDA_DST => {
                if (family == AF_INET and attr.data.len >= 4) {
                    @memcpy(&event.addr, attr.data[0..4]);
                }
            },
            NDA_LLADDR => {
                if (attr.data.len >= 6) @memcpy(&event.mac.bytes, attr.data[0..6]);
            },
            else => {},
        }
    }
    return event;
}

/// Parses one complete netlink message (header included).
pub fn parseOne(msg: []const u8) ?Event {
    if (msg.len < NLMSG_HDR_LEN) return null;
    const len = readU32(msg, 0) orelse return null;
    const typ = readU16(msg, 4) orelse return null;
    if (len < NLMSG_HDR_LEN or len > msg.len) return null;

    const payload = msg[NLMSG_HDR_LEN..len];
    return switch (typ) {
        RTM_NEWLINK => parseLinkEvent(payload, true),
        RTM_DELLINK => parseLinkEvent(payload, false),
        RTM_NEWADDR => parseAddrEvent(payload, true),
        RTM_DELADDR => parseAddrEvent(payload, false),
        RTM_NEWNEIGH => parseNeighEvent(payload, true),
        RTM_DELNEIGH => parseNeighEvent(payload, false),
        else => null,
    };
}

// --- monitor --------------------------------------------------------------

pub const Monitor = struct {
    fd: sys.fd_t,
    closed: bool = false,
    buf: [8192]u8 = undefined,
    buf_len: usize = 0,
    buf_off: usize = 0,

    pub fn open() PortError!Monitor {
        const fd = try sys.checkFd(linux.socket(
            linux.AF.NETLINK,
            @intCast(linux.SOCK.RAW | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
            NETLINK_ROUTE,
        ));
        errdefer sys.close(fd);

        var addr: linux.sockaddr.nl = .{
            .family = linux.AF.NETLINK,
            .pid = 0,
            .groups = RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
        };
        try sys.check(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));
        return .{ .fd = fd };
    }

    pub fn close(self: *Monitor) void {
        if (self.closed) return;
        sys.close(self.fd);
        self.closed = true;
    }

    /// Returns one event, or null when no message is pending. Coalesced
    /// messages from one datagram are preserved across calls.
    pub fn next(self: *Monitor) PortError!?Event {
        if (self.closed) return error.Closed;

        while (true) {
            while (self.buf_off + NLMSG_HDR_LEN <= self.buf_len) {
                const len = readU32(self.buf[0..self.buf_len], self.buf_off) orelse {
                    self.buf_off = self.buf_len;
                    break;
                };
                if (len < NLMSG_HDR_LEN or self.buf_off + len > self.buf_len) {
                    self.buf_off = self.buf_len;
                    break;
                }

                const msg = self.buf[self.buf_off .. self.buf_off + len];
                self.buf_off += std.mem.alignForward(usize, @as(usize, len), 4);

                const typ = readU16(msg, 4) orelse continue;
                if (typ == NLMSG_DONE or typ == NLMSG_ERROR) continue;
                if (parseOne(msg)) |event| return event;
            }

            self.buf_off = 0;
            self.buf_len = (try sys.read(self.fd, &self.buf)) orelse 0;
            if (self.buf_len == 0) return null;
        }
    }
};

// --- link dump ------------------------------------------------------------

const GetLinkReq = extern struct {
    hdr: NlMsgHdr,
    ifi: linux.ifinfomsg,
};

pub fn listLinks(io: std.Io, gpa: std.mem.Allocator) PortError![]LinkInfo {
    const fd = try sys.checkFd(linux.socket(
        linux.AF.NETLINK,
        @intCast(linux.SOCK.RAW | linux.SOCK.CLOEXEC),
        NETLINK_ROUTE,
    ));
    defer sys.close(fd);

    var addr: linux.sockaddr.nl = .{
        .family = linux.AF.NETLINK,
        .pid = 0,
        .groups = 0,
    };
    try sys.check(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));

    var req = GetLinkReq{
        .hdr = .{
            .len = @sizeOf(GetLinkReq),
            .type = RTM_GETLINK,
            .flags = NLM_F_REQUEST | NLM_F_DUMP,
            .seq = 1,
            .pid = 0,
        },
        .ifi = .{
            .family = linux.AF.UNSPEC,
            .type = 0,
            .index = 0,
            .flags = 0,
            .change = 0,
        },
    };
    try sys.check(linux.sendto(
        fd,
        std.mem.asBytes(&req).ptr,
        @sizeOf(GetLinkReq),
        0,
        null,
        0,
    ));

    var links: std.ArrayListUnmanaged(LinkInfo) = .empty;
    errdefer links.deinit(gpa);

    var buf: [8192]u8 = undefined;
    var idle_ticks: u32 = 0;

    dump: while (true) {
        const n = (try sys.read(fd, &buf)) orelse {
            if (idle_ticks >= 200) return error.Timeout;
            idle_ticks += 1;
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(5), .awake) catch return error.Interrupted;
            continue;
        };
        idle_ticks = 0;

        var off: usize = 0;
        while (off + NLMSG_HDR_LEN <= n) {
            const len = readU32(buf[0..n], off) orelse break;
            const typ = readU16(buf[0..n], off + 4) orelse break;
            if (len < NLMSG_HDR_LEN or off + len > n) break;

            const msg = buf[off .. off + len];
            off += std.mem.alignForward(usize, @as(usize, len), 4);

            switch (typ) {
                NLMSG_DONE => break :dump,
                NLMSG_ERROR => {
                    const error_code = readI32(msg, NLMSG_HDR_LEN) orelse return error.Io;
                    if (error_code != 0) return error.Io;
                },
                RTM_NEWLINK => {
                    const info = parseLinkData(msg[NLMSG_HDR_LEN..len]) orelse continue;
                    try links.append(gpa, .{
                        .index = info.index,
                        .name_buf = info.name_buf,
                        .name_len = info.name_len,
                        .mtu = info.mtu,
                        .mac = info.mac,
                        .up = info.up,
                        .running = info.running,
                        .operstate = info.operstate,
                        .master = info.master,
                    });
                },
                else => {},
            }
        }
    }

    return links.toOwnedSlice(gpa);
}

/// Returns the ifindex of the bridge master, or zero when the link is not
/// enslaved. Used by the control plane to refuse stealing an existing port.
pub fn linkMaster(io: std.Io, gpa: std.mem.Allocator, dev: []const u8) PortError!u32 {
    const links = try listLinks(io, gpa);
    defer gpa.free(links);
    for (links) |link| {
        if (std.mem.eql(u8, link.name(), dev)) return link.master;
    }
    return error.NotFound;
}

// --- control (mutations) --------------------------------------------------

const IfAddrMsg = extern struct {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

const RtMsg = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    flags: u32,
};

comptime {
    std.debug.assert(@sizeOf(IfAddrMsg) == 8);
    std.debug.assert(@sizeOf(RtMsg) == 12);
}

pub const RouteSpec = struct {
    prefix: types.Prefix4,
    via: ?types.Ipv4 = null,
    ifindex: u32,
    metric: u32 = 0,
    table: u32 = 0,
};

pub const Control = struct {
    fd: sys.fd_t,
    seq: u32 = 1,
    closed: bool = false,

    pub fn open() PortError!Control {
        const fd = try sys.checkFd(linux.socket(
            linux.AF.NETLINK,
            @intCast(linux.SOCK.RAW | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC),
            NETLINK_ROUTE,
        ));
        errdefer sys.close(fd);

        var addr: linux.sockaddr.nl = .{
            .family = linux.AF.NETLINK,
            .pid = 0,
            .groups = 0,
        };
        try sys.check(linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr))));
        return .{ .fd = fd };
    }

    pub fn close(self: *Control) void {
        if (self.closed) return;
        sys.close(self.fd);
        self.closed = true;
    }

    fn nextSeq(self: *Control) u32 {
        const seq = self.seq;
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return seq;
    }

    fn transact(self: *Control, io: std.Io, msg: []const u8, seq: u32) PortError!void {
        try sys.check(linux.sendto(self.fd, msg.ptr, msg.len, 0, null, 0));

        var buf: [4096]u8 = undefined;
        var idle_ticks: u32 = 0;
        while (true) {
            const n = (try sys.read(self.fd, &buf)) orelse {
                if (idle_ticks >= 200) return error.Timeout;
                idle_ticks += 1;
                std.Io.sleep(io, std.Io.Duration.fromMilliseconds(5), .awake) catch
                    return error.Interrupted;
                continue;
            };
            idle_ticks = 0;

            var off: usize = 0;
            while (off + NLMSG_HDR_LEN <= n) {
                const len = readU32(buf[0..n], off) orelse break;
                if (len < NLMSG_HDR_LEN or off + len > n) break;
                const typ = readU16(buf[0..n], off + 4) orelse break;
                const msg_seq = readU32(buf[0..n], off + 8) orelse break;
                if (typ == NLMSG_ERROR and msg_seq == seq) {
                    const err = readI32(buf[0..n], off + NLMSG_HDR_LEN) orelse return error.Io;
                    if (err == 0) return;
                    return mapNetlinkError(err);
                }
                off += std.mem.alignForward(usize, @as(usize, len), 4);
            }
        }
    }
};

fn mapNetlinkError(err: i32) PortError {
    const code: u32 = @intCast(-err);
    return switch (code) {
        1, 13 => error.PermissionDenied,
        2, 3, 19, 99 => error.NotFound,
        17 => error.Busy,
        22, 101 => error.InvalidArgument,
        95 => error.Unsupported,
        105 => error.NoBufferSpace,
        else => error.Io,
    };
}

fn buildAddrMessage(
    buf: []u8,
    typ: u16,
    flags: u16,
    seq: u32,
    ifindex: u32,
    prefix: types.Prefix4,
) []u8 {
    @memset(buf[0 .. NLMSG_HDR_LEN + @sizeOf(IfAddrMsg)], 0);
    const off0 = NLMSG_HDR_LEN;
    buf[off0] = AF_INET;
    buf[off0 + 1] = prefix.len;
    writeU32(buf, off0 + 4, ifindex);

    var off: usize = NLMSG_HDR_LEN + @sizeOf(IfAddrMsg);
    const addr = prefix.addr.toBytes();
    putAttr(buf, &off, IFA_LOCAL, &addr);
    putAttr(buf, &off, IFA_ADDRESS, &addr);

    writeU32(buf, 0, @intCast(off));
    writeU16(buf, 4, typ);
    writeU16(buf, 6, flags);
    writeU32(buf, 8, seq);
    writeU32(buf, 12, 0);
    return buf[0..off];
}

fn buildRouteMessage(
    buf: []u8,
    typ: u16,
    flags: u16,
    seq: u32,
    spec: RouteSpec,
) []u8 {
    @memset(buf[0 .. NLMSG_HDR_LEN + @sizeOf(RtMsg)], 0);
    const table: u32 = if (spec.table == 0) RT_TABLE_MAIN else spec.table;
    const table_byte: u8 = if (table <= 255) @intCast(table) else 0;

    const off0 = NLMSG_HDR_LEN;
    buf[off0] = AF_INET;
    buf[off0 + 1] = spec.prefix.len;
    buf[off0 + 4] = table_byte;
    buf[off0 + 5] = RTPROT_STATIC;
    buf[off0 + 6] = if (spec.via == null) RT_SCOPE_LINK else RT_SCOPE_UNIVERSE;
    buf[off0 + 7] = RTN_UNICAST;

    var off: usize = NLMSG_HDR_LEN + @sizeOf(RtMsg);
    const dst = spec.prefix.network().toBytes();
    putAttr(buf, &off, RTA_DST, &dst);
    if (spec.via) |via| {
        const gw = via.toBytes();
        putAttr(buf, &off, RTA_GATEWAY, &gw);
    }

    var oif: [4]u8 = undefined;
    std.mem.writeInt(u32, &oif, spec.ifindex, native_endian);
    putAttr(buf, &off, RTA_OIF, &oif);

    if (spec.metric != 0) {
        var metric: [4]u8 = undefined;
        std.mem.writeInt(u32, &metric, spec.metric, native_endian);
        putAttr(buf, &off, RTA_PRIORITY, &metric);
    }
    if (table > 255) {
        var table_attr: [4]u8 = undefined;
        std.mem.writeInt(u32, &table_attr, table, native_endian);
        putAttr(buf, &off, RTA_TABLE, &table_attr);
    }

    writeU32(buf, 0, @intCast(off));
    writeU16(buf, 4, typ);
    writeU16(buf, 6, flags);
    writeU32(buf, 8, seq);
    writeU32(buf, 12, 0);
    return buf[0..off];
}

pub fn addAddress(io: std.Io, dev: []const u8, prefix: types.Prefix4) PortError!void {
    const ifindex = try iface_mod.ifindex(dev);
    var control = try Control.open();
    defer control.close();

    var buf: [256]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildAddrMessage(
        &buf,
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        ifindex,
        prefix,
    );
    return control.transact(io, msg, seq);
}

pub fn deleteAddress(io: std.Io, dev: []const u8, prefix: types.Prefix4) PortError!void {
    const ifindex = try iface_mod.ifindex(dev);
    var control = try Control.open();
    defer control.close();

    var buf: [256]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildAddrMessage(
        &buf,
        RTM_DELADDR,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        ifindex,
        prefix,
    );
    return control.transact(io, msg, seq);
}

pub fn addRoute(io: std.Io, spec: RouteSpec) PortError!void {
    var control = try Control.open();
    defer control.close();

    var buf: [512]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildRouteMessage(
        &buf,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        spec,
    );
    return control.transact(io, msg, seq);
}

pub fn deleteRoute(io: std.Io, spec: RouteSpec) PortError!void {
    var control = try Control.open();
    defer control.close();

    var buf: [512]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildRouteMessage(
        &buf,
        RTM_DELROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        spec,
    );
    return control.transact(io, msg, seq);
}

// --- link and bridge mutations -------------------------------------------

const IFINFOMSG_LEN = 16;

pub const LinkKind = enum { bridge, veth };

pub const LinkCreateSpec = struct {
    name: []const u8,
    kind: LinkKind,
    peer: ?[]const u8 = null,
    stp: bool = false,
    vlan_filtering: bool = false,
};

fn beginLinkMessage(
    buf: []u8,
    typ: u16,
    flags: u16,
    seq: u32,
    family: u8,
    ifindex: u32,
) usize {
    @memset(buf[0 .. NLMSG_HDR_LEN + IFINFOMSG_LEN], 0);
    buf[NLMSG_HDR_LEN] = family;
    writeU32(buf, NLMSG_HDR_LEN + 4, ifindex);
    writeU32(buf, 8, seq);
    writeU32(buf, 12, 0);
    writeU16(buf, 4, typ);
    writeU16(buf, 6, flags);
    return NLMSG_HDR_LEN + IFINFOMSG_LEN;
}

fn finishMessage(buf: []u8, off: usize) []u8 {
    writeU32(buf, 0, @intCast(off));
    return buf[0..off];
}

fn beginNested(buf: []u8, off: *usize, typ: u16) usize {
    const start = off.*;
    putAttr(buf, off, typ, &.{});
    return start;
}

fn endNested(buf: []u8, off: usize, start: usize) void {
    writeU16(buf, start, @intCast(off - start));
}

fn putCString(buf: []u8, off: *usize, typ: u16, text: []const u8) void {
    var tmp: [64]u8 = undefined;
    @memcpy(tmp[0..text.len], text);
    tmp[text.len] = 0;
    putAttr(buf, off, typ, tmp[0 .. text.len + 1]);
}

fn putU16Attr(buf: []u8, off: *usize, typ: u16, value: u16) void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, value, native_endian);
    putAttr(buf, off, typ, &raw);
}

fn putU32Attr(buf: []u8, off: *usize, typ: u16, value: u32) void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, value, native_endian);
    putAttr(buf, off, typ, &raw);
}

fn putU8Attr(buf: []u8, off: *usize, typ: u16, value: u8) void {
    putAttr(buf, off, typ, &[_]u8{value});
}

fn buildLinkCreateMessage(
    buf: []u8,
    flags: u16,
    seq: u32,
    spec: LinkCreateSpec,
) []u8 {
    var off = beginLinkMessage(buf, RTM_NEWLINK, flags, seq, linux.AF.UNSPEC, 0);
    putCString(buf, &off, IFLA_IFNAME, spec.name);

    const linkinfo = beginNested(buf, &off, IFLA_LINKINFO);
    putCString(buf, &off, IFLA_INFO_KIND, switch (spec.kind) {
        .bridge => "bridge",
        .veth => "veth",
    });

    const data = beginNested(buf, &off, IFLA_INFO_DATA);
    switch (spec.kind) {
        .bridge => {
            putU32Attr(buf, &off, IFLA_BR_STP_STATE, if (spec.stp) 1 else 0);
            putU8Attr(buf, &off, IFLA_BR_VLAN_FILTERING, if (spec.vlan_filtering) 1 else 0);
            putU16Attr(buf, &off, IFLA_BR_VLAN_DEFAULT_PVID, if (spec.vlan_filtering) 0 else 1);
        },
        .veth => {
            const peer = spec.peer orelse "";
            const peer_attr = beginNested(buf, &off, VETH_INFO_PEER);
            @memset(buf[off .. off + IFINFOMSG_LEN], 0);
            off += IFINFOMSG_LEN;
            putCString(buf, &off, IFLA_IFNAME, peer);
            endNested(buf, off, peer_attr);
        },
    }
    endNested(buf, off, data);
    endNested(buf, off, linkinfo);
    return finishMessage(buf, off);
}

fn buildBridgeVlanMessage(
    buf: []u8,
    typ: u16,
    seq: u32,
    ifindex: u32,
    vid: u16,
    pvid: bool,
    untagged: bool,
) []u8 {
    var off = beginLinkMessage(buf, typ, NLM_F_REQUEST | NLM_F_ACK, seq, AF_BRIDGE, ifindex);
    const afspec = beginNested(buf, &off, IFLA_AF_SPEC);
    putU16Attr(buf, &off, IFLA_BRIDGE_FLAGS, 0);
    var vlan_flags: u16 = 0;
    if (pvid) vlan_flags |= BRIDGE_VLAN_INFO_PVID;
    if (untagged) vlan_flags |= BRIDGE_VLAN_INFO_UNTAGGED;
    var vlan_info: [4]u8 = undefined;
    std.mem.writeInt(u16, vlan_info[0..2], vlan_flags, native_endian);
    std.mem.writeInt(u16, vlan_info[2..4], vid, native_endian);
    putAttr(buf, &off, IFLA_BRIDGE_VLAN_INFO, &vlan_info);
    endNested(buf, off, afspec);
    return finishMessage(buf, off);
}

pub fn createLink(io: std.Io, spec: LinkCreateSpec) PortError!void {
    try sys.validateName(spec.name);
    if (spec.kind == .veth) try sys.validateName(spec.peer orelse return error.InvalidArgument);

    var control = try Control.open();
    defer control.close();

    var buf: [1024]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildLinkCreateMessage(
        &buf,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        spec,
    );
    return control.transact(io, msg, seq);
}

pub fn deleteLink(io: std.Io, dev: []const u8) PortError!void {
    const ifindex = try iface_mod.ifindex(dev);
    var control = try Control.open();
    defer control.close();

    var buf: [256]u8 = undefined;
    const seq = control.nextSeq();
    const off = beginLinkMessage(&buf, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq, linux.AF.UNSPEC, ifindex);
    const msg = finishMessage(&buf, off);
    return control.transact(io, msg, seq);
}

pub fn setMaster(io: std.Io, dev: []const u8, master: ?[]const u8) PortError!void {
    const ifindex = try iface_mod.ifindex(dev);
    const master_index: u32 = if (master) |name| try iface_mod.ifindex(name) else 0;

    var control = try Control.open();
    defer control.close();

    var buf: [256]u8 = undefined;
    const seq = control.nextSeq();
    var off = beginLinkMessage(&buf, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq, linux.AF.UNSPEC, ifindex);
    putU32Attr(&buf, &off, IFLA_MASTER, master_index);
    const msg = finishMessage(&buf, off);
    return control.transact(io, msg, seq);
}

pub fn setBridgeVlan(
    io: std.Io,
    dev: []const u8,
    vid: u16,
    pvid: bool,
    untagged: bool,
    add: bool,
) PortError!void {
    if (vid == 0 or vid > 4094) return error.InvalidArgument;
    if (pvid and !untagged) return error.InvalidArgument;
    const ifindex = try iface_mod.ifindex(dev);

    var control = try Control.open();
    defer control.close();

    var buf: [512]u8 = undefined;
    const seq = control.nextSeq();
    const msg = buildBridgeVlanMessage(
        &buf,
        if (add) RTM_SETLINK else RTM_DELLINK,
        seq,
        ifindex,
        vid,
        pvid,
        untagged,
    );
    return control.transact(io, msg, seq);
}

// --- tests ----------------------------------------------------------------

fn getAttr(attrs: []const u8, typ: u16) ?[]const u8 {
    var off: usize = 0;
    while (off + 4 <= attrs.len) {
        const len = readU16(attrs, off) orelse return null;
        const attr_type = readU16(attrs, off + 2) orelse return null;
        if (len < 4 or off + len > attrs.len) return null;
        if (attr_type == typ) return attrs[off + 4 .. off + len];
        off += std.mem.alignForward(usize, @as(usize, len), 4);
    }
    return null;
}

fn putAttr(buf: []u8, off: *usize, typ: u16, data: []const u8) void {
    const len: u16 = @intCast(4 + data.len);
    writeU16(buf, off.*, len);
    writeU16(buf, off.* + 2, typ);
    @memcpy(buf[off.* + 4 .. off.* + 4 + data.len], data);
    const padded = std.mem.alignForward(usize, @as(usize, len), 4);
    @memset(buf[off.* + 4 + data.len .. off.* + padded], 0);
    off.* += padded;
}

fn buildLinkMessage(buf: []u8) []u8 {
    var off: usize = 0;
    writeU32(buf, 0, 0); // patched below
    writeU16(buf, 4, RTM_NEWLINK);
    writeU16(buf, 6, 0);
    writeU32(buf, 8, 1);
    writeU32(buf, 12, 0);
    off = NLMSG_HDR_LEN;

    buf[off] = 0; // family
    buf[off + 1] = 0;
    writeU16(buf, off + 2, 1); // type
    std.mem.writeInt(i32, @ptrCast(buf[off + 4 ..][0..4]), 7, native_endian);
    writeU32(buf, off + 8, IFF_UP | IFF_RUNNING);
    writeU32(buf, off + 12, 0);
    off += NLMSG_HDR_LEN;

    putAttr(buf, &off, IFLA_IFNAME, "veth-test\x00");
    var mtu: [4]u8 = undefined;
    std.mem.writeInt(u32, &mtu, 1500, native_endian);
    putAttr(buf, &off, IFLA_MTU, &mtu);
    putAttr(buf, &off, IFLA_ADDRESS, &[_]u8{ 0x02, 0, 0, 0, 0, 1 });
    putAttr(buf, &off, IFLA_OPERSTATE, &[_]u8{IF_OPER_UP});

    writeU32(buf, 0, @intCast(off));
    return buf[0..off];
}

test "parses RTM_NEWLINK" {
    var buf: [256]u8 = undefined;
    const msg = buildLinkMessage(&buf);

    const event = parseOne(msg).?;
    try std.testing.expectEqual(Kind.link, event.kind);
    try std.testing.expectEqual(Action.add, event.action);
    try std.testing.expectEqual(@as(u32, 7), event.index);
    try std.testing.expectEqualStrings("veth-test", event.name());
    try std.testing.expectEqual(@as(u16, 1500), event.mtu);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0, 0, 0, 0, 1 }, &event.mac.bytes);
    try std.testing.expect(event.up);
}

test "rejects truncated and malformed messages" {
    var buf: [256]u8 = undefined;
    const msg = buildLinkMessage(&buf);

    try std.testing.expect(parseOne(msg[0..8]) == null);
    try std.testing.expect(parseOne(msg[0 .. msg.len - 1]) == null);

    // Attribute length zero.
    var bad: [256]u8 = undefined;
    @memcpy(bad[0..msg.len], msg);
    writeU16(&bad, NLMSG_HDR_LEN + NLMSG_HDR_LEN, 0);
    try std.testing.expect(parseOne(bad[0..msg.len]) != null); // stops at bad attr

    // Message length larger than the buffer.
    var bad_len: [256]u8 = undefined;
    @memcpy(bad_len[0..msg.len], msg);
    writeU32(&bad_len, 0, @intCast(msg.len + 4));
    try std.testing.expect(parseOne(bad_len[0..msg.len]) == null);
}

test "parses RTM_NEWADDR" {
    var buf: [128]u8 = undefined;
    var off: usize = NLMSG_HDR_LEN;
    buf[off] = AF_INET;
    buf[off + 1] = 24;
    buf[off + 2] = 0;
    buf[off + 3] = 0;
    writeU32(&buf, off + 4, 9);
    off += 8;
    putAttr(&buf, &off, IFA_ADDRESS, &[_]u8{ 10, 0, 0, 5 });
    putAttr(&buf, &off, IFA_LOCAL, &[_]u8{ 10, 0, 0, 6 });

    writeU32(&buf, 0, @intCast(off));
    writeU16(&buf, 4, RTM_NEWADDR);
    writeU16(&buf, 6, 0);
    writeU32(&buf, 8, 2);
    writeU32(&buf, 12, 0);

    const event = parseOne(buf[0..off]).?;
    try std.testing.expectEqual(Kind.addr, event.kind);
    try std.testing.expectEqual(Action.add, event.action);
    try std.testing.expectEqual(@as(u32, 9), event.index);
    try std.testing.expectEqual(@as(u8, 24), event.prefix_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 6 }, &event.addr);
}

test "parses RTM_DELNEIGH" {
    var buf: [128]u8 = undefined;
    var off: usize = NLMSG_HDR_LEN;
    buf[off] = AF_INET;
    buf[off + 1] = 0;
    writeU16(&buf, off + 2, 0);
    writeU32(&buf, off + 4, 3);
    writeU16(&buf, off + 8, 0x02);
    buf[off + 10] = 0;
    buf[off + 11] = 0;
    off += 12;
    putAttr(&buf, &off, NDA_DST, &[_]u8{ 10, 0, 0, 2 });
    putAttr(&buf, &off, NDA_LLADDR, &[_]u8{ 0x02, 0, 0, 0, 0, 2 });

    writeU32(&buf, 0, @intCast(off));
    writeU16(&buf, 4, RTM_DELNEIGH);
    writeU16(&buf, 6, 0);
    writeU32(&buf, 8, 3);
    writeU32(&buf, 12, 0);

    const event = parseOne(buf[0..off]).?;
    try std.testing.expectEqual(Kind.neigh, event.kind);
    try std.testing.expectEqual(Action.del, event.action);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 2 }, &event.addr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0, 0, 0, 0, 2 }, &event.mac.bytes);
}

test "builds RTM_NEWADDR message" {
    var buf: [256]u8 = undefined;
    const prefix = try types.Prefix4.parse("10.0.1.1/24");
    const msg = buildAddrMessage(&buf, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, 7, 42, prefix);

    try std.testing.expectEqual(@as(u16, RTM_NEWADDR), readU16(msg, 4).?);
    try std.testing.expectEqual(@as(u32, 7), readU32(msg, 8).?);
    try std.testing.expectEqual(@as(u32, @intCast(msg.len)), readU32(msg, 0).?);
    try std.testing.expectEqual(AF_INET, msg[NLMSG_HDR_LEN]);
    try std.testing.expectEqual(@as(u8, 24), msg[NLMSG_HDR_LEN + 1]);
    try std.testing.expectEqual(@as(u32, 42), readU32(msg, NLMSG_HDR_LEN + 4).?);

    const first = getAttr(msg[NLMSG_HDR_LEN + 8 ..], IFA_LOCAL).?;
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 1, 1 }, first);
}

test "builds RTM_NEWROUTE message" {
    var buf: [512]u8 = undefined;
    const spec = RouteSpec{
        .prefix = try types.Prefix4.parse("10.2.0.0/16"),
        .via = try types.Ipv4.parse("10.0.1.1"),
        .ifindex = 5,
        .metric = 50,
    };
    const msg = buildRouteMessage(&buf, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, 9, spec);

    try std.testing.expectEqual(@as(u16, RTM_NEWROUTE), readU16(msg, 4).?);
    try std.testing.expectEqual(@as(u32, 9), readU32(msg, 8).?);
    try std.testing.expectEqual(AF_INET, msg[NLMSG_HDR_LEN]);
    try std.testing.expectEqual(@as(u8, 16), msg[NLMSG_HDR_LEN + 1]);
    try std.testing.expectEqual(@as(u8, 254), msg[NLMSG_HDR_LEN + 4]);
    try std.testing.expectEqual(RTPROT_STATIC, msg[NLMSG_HDR_LEN + 5]);
    try std.testing.expectEqual(RT_SCOPE_UNIVERSE, msg[NLMSG_HDR_LEN + 6]);

    const attrs = msg[NLMSG_HDR_LEN + 12 ..];
    try std.testing.expectEqualSlices(u8, &.{ 10, 2, 0, 0 }, getAttr(attrs, RTA_DST).?);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 1, 1 }, getAttr(attrs, RTA_GATEWAY).?);
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, getAttr(attrs, RTA_OIF).?[0..4], native_endian));
    try std.testing.expectEqual(@as(u32, 50), std.mem.readInt(u32, getAttr(attrs, RTA_PRIORITY).?[0..4], native_endian));
}

test "builds bridge create message" {
    var buf: [1024]u8 = undefined;
    const msg = buildLinkCreateMessage(&buf, NLM_F_REQUEST | NLM_F_ACK, 11, .{
        .name = "vnatbr0",
        .kind = .bridge,
        .stp = true,
        .vlan_filtering = true,
    });

    try std.testing.expectEqual(@as(u16, RTM_NEWLINK), readU16(msg, 4).?);
    const attrs = msg[NLMSG_HDR_LEN + IFINFOMSG_LEN ..];
    try std.testing.expectEqualStrings("vnatbr0", std.mem.sliceTo(getAttr(attrs, IFLA_IFNAME).?, 0));
    const linkinfo = getAttr(attrs, IFLA_LINKINFO).?;
    try std.testing.expectEqualStrings("bridge", std.mem.sliceTo(getAttr(linkinfo, IFLA_INFO_KIND).?, 0));
    const data = getAttr(linkinfo, IFLA_INFO_DATA).?;
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, getAttr(data, IFLA_BR_STP_STATE).?[0..4], native_endian));
    try std.testing.expectEqual(@as(u8, 1), getAttr(data, IFLA_BR_VLAN_FILTERING).?[0]);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, getAttr(data, IFLA_BR_VLAN_DEFAULT_PVID).?[0..2], native_endian));
}

test "builds veth create message with peer" {
    var buf: [1024]u8 = undefined;
    const msg = buildLinkCreateMessage(&buf, NLM_F_REQUEST | NLM_F_ACK, 12, .{
        .name = "vnatp0",
        .kind = .veth,
        .peer = "vnatb0",
    });

    const attrs = msg[NLMSG_HDR_LEN + IFINFOMSG_LEN ..];
    const linkinfo = getAttr(attrs, IFLA_LINKINFO).?;
    try std.testing.expectEqualStrings("veth", std.mem.sliceTo(getAttr(linkinfo, IFLA_INFO_KIND).?, 0));
    const data = getAttr(linkinfo, IFLA_INFO_DATA).?;
    const peer = getAttr(data, VETH_INFO_PEER).?;
    try std.testing.expect(peer.len >= IFINFOMSG_LEN);
    try std.testing.expectEqualStrings("vnatb0", std.mem.sliceTo(getAttr(peer[IFINFOMSG_LEN..], IFLA_IFNAME).?, 0));
}

test "builds bridge vlan message" {
    var buf: [512]u8 = undefined;
    const msg = buildBridgeVlanMessage(&buf, RTM_SETLINK, 13, 42, 10, true, true);

    try std.testing.expectEqual(@as(u16, RTM_SETLINK), readU16(msg, 4).?);
    try std.testing.expectEqual(AF_BRIDGE, msg[NLMSG_HDR_LEN]);
    try std.testing.expectEqual(@as(u32, 42), readU32(msg, NLMSG_HDR_LEN + 4).?);
    const afspec = getAttr(msg[NLMSG_HDR_LEN + IFINFOMSG_LEN ..], IFLA_AF_SPEC).?;
    const info = getAttr(afspec, IFLA_BRIDGE_VLAN_INFO).?;
    try std.testing.expectEqual(@as(u16, BRIDGE_VLAN_INFO_PVID | BRIDGE_VLAN_INFO_UNTAGGED), std.mem.readInt(u16, info[0..2], native_endian));
    try std.testing.expectEqual(@as(u16, 10), std.mem.readInt(u16, info[2..4], native_endian));
}

test "netlink error mapping" {
    try std.testing.expectEqual(PortError.PermissionDenied, mapNetlinkError(-13));
    try std.testing.expectEqual(PortError.NotFound, mapNetlinkError(-2));
    try std.testing.expectEqual(PortError.Busy, mapNetlinkError(-17));
    try std.testing.expectEqual(PortError.InvalidArgument, mapNetlinkError(-22));
    try std.testing.expectEqual(PortError.Io, mapNetlinkError(-999));
}
