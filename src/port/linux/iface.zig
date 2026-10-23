//! Interface control via `SIOCGIF*`/`SIOCSIF*` ioctls.
//!
//! These helpers use a temporary AF_INET dgram socket. They are control-plane
//! only (open/configure/refresh), never called per packet.

const std = @import("std");
const linux = std.os.linux;
const sys = @import("sys.zig");
const types = @import("../../types.zig");
const PortError = @import("../../errors.zig").PortError;

const IFF_UP: u16 = 0x1;
const ARPHRD_ETHER: u16 = 1;

fn makeIfReq(name: []const u8) PortError!linux.ifreq {
    try sys.validateName(name);
    var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(ifr.ifrn.name[0..name.len], name);
    return ifr;
}

pub fn ifindex(name: []const u8) PortError!u32 {
    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    try sys.ioctl(fd, linux.SIOCGIFINDEX, &ifr);
    if (ifr.ifru.ivalue <= 0) return error.NotFound;
    return @intCast(ifr.ifru.ivalue);
}

pub fn mtu(name: []const u8) PortError!u16 {
    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    try sys.ioctl(fd, linux.SIOCGIFMTU, &ifr);
    if (ifr.ifru.mtu < 68 or ifr.ifru.mtu > 65535) return error.InvalidArgument;
    return @intCast(ifr.ifru.mtu);
}

pub fn mac(name: []const u8) PortError!types.Mac {
    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    try sys.ioctl(fd, linux.SIOCGIFHWADDR, &ifr);
    if (ifr.ifru.hwaddr.family != ARPHRD_ETHER) return .{};

    var out: types.Mac = .{};
    @memcpy(&out.bytes, ifr.ifru.hwaddr.data[0..6]);
    return out;
}

pub fn flags(name: []const u8) PortError!u16 {
    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    try sys.ioctl(fd, linux.SIOCGIFFLAGS, &ifr);
    return @bitCast(ifr.ifru.flags);
}

pub fn setFlags(name: []const u8, value: u16) PortError!void {
    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    ifr.ifru.flags = @bitCast(value);
    try sys.ioctl(fd, linux.SIOCSIFFLAGS, &ifr);
}

pub fn isUp(name: []const u8) PortError!bool {
    return (try flags(name)) & IFF_UP != 0;
}

pub fn setUp(name: []const u8, up: bool) PortError!void {
    var value = try flags(name);
    if (up) {
        value |= IFF_UP;
    } else {
        value &= ~IFF_UP;
    }
    try setFlags(name, value);
}

pub fn setMtu(name: []const u8, value: u16) PortError!void {
    if (value < 576 or value > 9000) return error.InvalidArgument;

    const fd = try sys.controlSocket();
    defer sys.close(fd);

    var ifr = try makeIfReq(name);
    ifr.ifru.mtu = @intCast(value);
    try sys.ioctl(fd, linux.SIOCSIFMTU, &ifr);
}
