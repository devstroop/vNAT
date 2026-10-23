//! Port abstraction.
//!
//! A port is a source/sink of frames (L2) or packets (L3). The datapath holds
//! ports behind this vtable so the forwarding pipeline is independent of
//! AF_PACKET, TUN/TAP, VpnService fds and in-memory test ports.

const std = @import("std");
const types = @import("../types.zig");
const PortError = @import("../errors.zig").PortError;

pub const PortId = types.PortId;

pub const PortKind = enum {
    ethernet,
    wifi,
    cellular,
    usb,
    tun,
    tap,
    bridge,
    memory,
};

pub const Capabilities = struct {
    l2: bool = false,
    l3: bool = false,
    promiscuous: bool = false,
    multicast: bool = false,
    vlan_filter: bool = false,
    checksum_offload: bool = false,
    gso: bool = false,
    can_set_mtu: bool = false,
};

pub const LinkState = enum { unknown, down, up };

pub const PortInfo = struct {
    id: PortId,
    name: []const u8,
    ifindex: u32 = 0,
    kind: PortKind,
    mac: types.Mac = .{},
    mtu: u16 = 1500,
    link: LinkState = .unknown,
    capabilities: Capabilities = .{},
};

pub const Stats = struct {
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    drops: u64 = 0,
};

/// A port handle. The concrete implementation owns `ctx`; `Port` is copied by
/// value and is only valid while the implementation is alive.
pub const Port = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ctx: *anyopaque, io: std.Io, buf: []u8) PortError!?usize,
        write: *const fn (ctx: *anyopaque, io: std.Io, frame: []const u8) PortError!void,
        info: *const fn (ctx: *anyopaque) PortInfo,
        stats: *const fn (ctx: *anyopaque) Stats,
        refresh: *const fn (ctx: *anyopaque, io: std.Io) PortError!void,
        setUp: *const fn (ctx: *anyopaque, io: std.Io, up: bool) PortError!void,
        setMtu: *const fn (ctx: *anyopaque, io: std.Io, mtu: u16) PortError!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };

    /// Returns null when no frame is currently available. Implementations must
    /// not block the caller indefinitely; use `io` for any required waits.
    pub fn read(self: Port, io: std.Io, buf: []u8) PortError!?usize {
        return self.vtable.read(self.ctx, io, buf);
    }

    pub fn write(self: Port, io: std.Io, frame: []const u8) PortError!void {
        return self.vtable.write(self.ctx, io, frame);
    }

    pub fn info(self: Port) PortInfo {
        return self.vtable.info(self.ctx);
    }

    pub fn stats(self: Port) Stats {
        return self.vtable.stats(self.ctx);
    }

    /// Re-reads link state, MTU and MAC from the OS. Used after hotplug events.
    pub fn refresh(self: Port, io: std.Io) PortError!void {
        return self.vtable.refresh(self.ctx, io);
    }

    pub fn setUp(self: Port, io: std.Io, up: bool) PortError!void {
        return self.vtable.setUp(self.ctx, io, up);
    }

    pub fn setMtu(self: Port, io: std.Io, mtu: u16) PortError!void {
        return self.vtable.setMtu(self.ctx, io, mtu);
    }

    pub fn deinit(self: Port, io: std.Io) void {
        self.vtable.close(self.ctx, io);
    }
};
