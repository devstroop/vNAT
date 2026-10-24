//! Port manager: opens configured ports, assigns stable IDs and pumps
//! rtnetlink hotplug events.
//!
//! Linux-only for R1. Ports are allocated from the manager's arena so their
//! `Port.ctx` pointers stay stable even if the entry list grows.

const std = @import("std");
const schema = @import("../config/schema.zig");
const port_mod = @import("port.zig");
const types = @import("../types.zig");
const PortError = @import("../errors.zig").PortError;
const linux = @import("linux/root.zig");
const fd_port = @import("fd.zig");

pub const Entry = struct {
    config_name: []const u8,
    port: port_mod.Port,
};

pub const ExtraPort = struct {
    config_name: []const u8,
    device: []const u8,
    mtu: ?u16 = null,
};

pub const InjectedPort = struct {
    config_name: []const u8,
    fd: std.posix.fd_t,
};

pub const OpenOptions = struct {
    /// Config ports that must not be opened (kernel-offloaded bridge members).
    skip: []const []const u8 = &.{},
    /// Synthetic ports opened after configured ports (veth trunk endpoints).
    extras: []const ExtraPort = &.{},
    /// L3 ports supplied by the host (Android VpnService fd) instead of opened
    /// from the config.
    injected: []const InjectedPort = &.{},
};

pub const Manager = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    entries: []Entry = &.{},
    monitor: ?linux.netlink.Monitor = null,

    pub fn openFromConfig(
        gpa: std.mem.Allocator,
        io: std.Io,
        cfg: *const schema.Config,
    ) PortError!Manager {
        return openFromConfigWithOptions(gpa, io, cfg, .{});
    }

    pub fn openFromConfigWithOptions(
        gpa: std.mem.Allocator,
        io: std.Io,
        cfg: *const schema.Config,
        options: OpenOptions,
    ) PortError!Manager {
        var self = Manager{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
        errdefer self.deinit(io);

        const a = self.arena.allocator();
        var list: std.ArrayListUnmanaged(Entry) = .empty;
        errdefer {
            for (list.items) |entry| entry.port.deinit(io);
        }

        var next_id: u32 = 1;
        var it = cfg.ports.iterator();
        while (it.next()) |map_entry| {
            if (optionallySkipped(options.skip, map_entry.key_ptr.*)) continue;

            const id = types.PortId{ .value = next_id };
            next_id += 1;

            const port = if (findInjected(options.injected, map_entry.key_ptr.*)) |injected| blk: {
                const port_cfg = map_entry.value_ptr.*;
                if (port_cfg.kind != .l3 or port_cfg.create != null) return error.InvalidArgument;
                const p = try fd_port.FdPort.open(a, io, id, .{
                    .fd = injected.fd,
                    .name = port_cfg.device,
                    .mtu = port_cfg.mtu orelse 1380,
                });
                break :blk p.port();
            } else try openOne(a, io, id, map_entry.value_ptr.*);
            errdefer port.deinit(io);

            try list.append(a, .{
                .config_name = try a.dupe(u8, map_entry.key_ptr.*),
                .port = port,
            });
        }

        for (options.extras) |extra| {
            const id = types.PortId{ .value = next_id };
            next_id += 1;

            const port = try openOne(a, io, id, .{
                .kind = .l2,
                .device = extra.device,
                .mtu = extra.mtu,
            });
            errdefer port.deinit(io);

            try list.append(a, .{
                .config_name = try a.dupe(u8, extra.config_name),
                .port = port,
            });
        }

        for (options.injected, 0..) |injected, i| {
            if (findInjected(options.injected[0..i], injected.config_name) != null) {
                return error.InvalidArgument;
            }
            if (!cfg.ports.contains(injected.config_name) or
                optionallySkipped(options.skip, injected.config_name))
            {
                return error.InvalidArgument;
            }
        }

        self.entries = try list.toOwnedSlice(a);
        return self;
    }

    pub fn deinit(self: *Manager, io: std.Io) void {
        if (self.monitor) |*monitor| monitor.close();
        for (self.entries) |entry| entry.port.deinit(io);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Opens the rtnetlink monitor. `vrouterd` requires it; one-shot commands can
    /// skip it.
    pub fn enableMonitor(self: *Manager) PortError!void {
        if (self.monitor != null) return;
        self.monitor = try linux.netlink.Monitor.open();
    }

    pub fn count(self: *const Manager) usize {
        return self.entries.len;
    }

    pub fn entryAt(self: *const Manager, index: usize) ?Entry {
        if (index >= self.entries.len) return null;
        return self.entries[index];
    }

    pub fn get(self: *const Manager, config_name: []const u8) ?port_mod.Port {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.config_name, config_name)) return entry.port;
        }
        return null;
    }

    /// Re-reads link state for every port.
    pub fn refreshAll(self: *Manager, io: std.Io) PortError!void {
        for (self.entries) |entry| {
            entry.port.refresh(io) catch |err| switch (err) {
                error.NotFound => {},
                else => return err,
            };
        }
    }

    /// Returns the next hotplug event, refreshing matching ports first.
    pub fn poll(self: *Manager, io: std.Io) PortError!?linux.netlink.Event {
        const monitor = if (self.monitor) |*m| m else return null;
        const event = (try monitor.next()) orelse return null;

        if (event.kind == .link) {
            for (self.entries) |entry| {
                if (entry.port.info().ifindex != event.index) continue;
                entry.port.refresh(io) catch |err| switch (err) {
                    error.NotFound => {},
                    else => return err,
                };
            }
        }
        return event;
    }

    fn findInjected(injected: []const InjectedPort, name: []const u8) ?InjectedPort {
        for (injected) |item| {
            if (std.mem.eql(u8, item.config_name, name)) return item;
        }
        return null;
    }

    fn optionallySkipped(skip: []const []const u8, name: []const u8) bool {
        for (skip) |item| {
            if (std.mem.eql(u8, item, name)) return true;
        }
        return false;
    }

    fn openOne(
        a: std.mem.Allocator,
        io: std.Io,
        id: types.PortId,
        cfg: schema.PortConfig,
    ) PortError!port_mod.Port {
        switch (cfg.kind) {
            .l2 => {
                if (cfg.create) |create| {
                    switch (create) {
                        .tap => {
                            const p = try linux.tun.TunPort.open(a, io, id, .{
                                .name = cfg.device,
                                .tap = true,
                                .mtu = cfg.mtu,
                            });
                            errdefer p.port().deinit(io);
                            try p.port().setUp(io, true);
                            return p.port();
                        },
                        .tun => return error.InvalidArgument,
                    }
                }

                const p = try linux.af_packet.AfPacketPort.open(a, io, id, .{
                    .name = cfg.device,
                });
                errdefer p.port().deinit(io);
                if (cfg.mtu) |mtu| try p.port().setMtu(io, mtu);
                return p.port();
            },
            .l3 => {
                if (cfg.create) |create| {
                    switch (create) {
                        .tun => {
                            const p = try linux.tun.TunPort.open(a, io, id, .{
                                .name = cfg.device,
                                .tap = false,
                                .mtu = cfg.mtu,
                            });
                            errdefer p.port().deinit(io);
                            try p.port().setUp(io, true);
                            return p.port();
                        },
                        .tap => return error.InvalidArgument,
                    }
                }
                // An existing L3 device is owned by whoever created its fd.
                return error.Unsupported;
            },
        }
    }
};
