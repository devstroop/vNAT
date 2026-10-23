const std = @import("std");
const vnat = @import("vnat");

const max_config_bytes = 4 * 1024 * 1024;
const default_config = "/etc/vnat/vnat.json";

const DhcpLeaseWire = struct {
    server: []const u8,
    port: u32,
    ip: []const u8,
    mac: []const u8,
    state: []const u8,
    expires_ms: i64,
};

const DhcpLeaseDbWire = struct {
    version: u32,
    leases: []const DhcpLeaseWire,
};

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "vnat: {s}\n", .{@errorName(err)}) catch "vnat: error\n";
        std.Io.File.stderr().writeStreamingAll(init.io, msg) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        try usage(io);
        return;
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "version") or
        std.mem.eql(u8, cmd, "--version") or
        std.mem.eql(u8, cmd, "-V"))
    {
        try print(io, gpa, "vnat {s}\n", .{vnat.version});
        return;
    }

    if (std.mem.eql(u8, cmd, "help") or
        std.mem.eql(u8, cmd, "--help") or
        std.mem.eql(u8, cmd, "-h"))
    {
        try usage(io);
        return;
    }

    if (std.mem.eql(u8, cmd, "validate")) {
        if (args.len != 3) {
            try usage(io);
            std.process.exit(2);
        }
        const code = try validateFile(io, gpa, args[2]);
        if (code != 0) std.process.exit(code);
        return;
    }

    if (std.mem.eql(u8, cmd, "port")) {
        if (args.len == 3 and std.mem.eql(u8, args[2], "list")) {
            const code = try portList(io, gpa);
            if (code != 0) std.process.exit(code);
            return;
        }
    }

    if (std.mem.eql(u8, cmd, "iface")) {
        try ifaceCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "route")) {
        try routeCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "down")) {
        try downCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "journal")) {
        try journalCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "bridge")) {
        try bridgeCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "status")) {
        const path = configPath(args[2..]) catch {
            try usage(io);
            std.process.exit(2);
        };
        const code = try statusFile(io, gpa, path);
        if (code != 0) std.process.exit(code);
        return;
    }

    if (std.mem.eql(u8, cmd, "selftest")) {
        const code = try selfTest(io, gpa, args[2..]);
        if (code != 0) std.process.exit(code);
        return;
    }

    if (std.mem.eql(u8, cmd, "dhcp")) {
        try dhcpCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "firewall")) {
        try firewallCommand(init, args[2..]);
        return;
    }

    if (std.mem.eql(u8, cmd, "dns")) {
        try dnsCommand(init, args[2..]);
        return;
    }

    try printErr(io, gpa, "unknown command '{s}'\n", .{cmd});
    try usage(io);
    std.process.exit(2);
}

const ConfigArgs = struct {
    rest: []const []const u8,
    path: []const u8,
};

fn splitConfig(args: []const []const u8) ConfigArgs {
    if (args.len >= 2) {
        const n = args.len;
        if (std.mem.eql(u8, args[n - 2], "-c") or
            std.mem.eql(u8, args[n - 2], "--config"))
        {
            return .{ .rest = args[0 .. n - 2], .path = args[n - 1] };
        }
    }
    return .{ .rest = args, .path = default_config };
}

fn stateDir(init: std.process.Init) []const u8 {
    return init.environ_map.get("VNAT_RUN_DIR") orelse "/run/vnat";
}

fn loadConfig(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !vnat.config_parse.Parsed {
    const source = try readConfig(io, gpa, path);
    defer gpa.free(source);

    var parsed = try vnat.config_parse.parse(gpa, source);
    errdefer parsed.deinit();
    try vnat.config_validate.validate(&parsed.config);
    return parsed;
}

fn openHost(init: std.process.Init, parsed: *const vnat.config_parse.Parsed) !vnat.control_host.Host {
    return vnat.control_host.Host.init(
        init.io,
        init.gpa,
        stateDir(init),
        parsed.config.instance,
    );
}

fn reportHostError(io: std.Io, gpa: std.mem.Allocator, action: []const u8, err: anyerror) !void {
    if (err == error.NotManaged) {
        try printErr(io, gpa, "vnat: {s}: not managed by vnat (use ip addr/route del)\n", .{action});
        return;
    }
    try printErr(io, gpa, "vnat: {s}: {s}\n", .{ action, @errorName(err) });
}

fn ifaceCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len < 2) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    var host = openHost(init, &parsed) catch |err| {
        try reportHostError(io, gpa, "state", err);
        std.process.exit(1);
    };
    defer host.deinit();

    const action = cfg.rest[0];
    if (std.mem.eql(u8, action, "set")) {
        if (cfg.rest.len != 3) {
            try usage(io);
            std.process.exit(2);
        }
        const change = host.ifaceSet(cfg.rest[1], cfg.rest[2]) catch |err| {
            if (err == error.Busy) {
                try printErr(io, gpa, "vnat: iface set: address already exists and is not managed by vnat\n", .{});
                std.process.exit(1);
            }
            try reportHostError(io, gpa, "iface set", err);
            std.process.exit(1);
        };
        try print(io, gpa, "ok: {s} {s}{s}\n", .{
            cfg.rest[1],
            cfg.rest[2],
            if (change == .noop) " (already configured)" else "",
        });
        return;
    }

    if (std.mem.eql(u8, action, "del")) {
        if (cfg.rest.len != 3) {
            try usage(io);
            std.process.exit(2);
        }
        const change = host.ifaceDel(cfg.rest[1], cfg.rest[2]) catch |err| {
            try reportHostError(io, gpa, "iface del", err);
            std.process.exit(1);
        };
        try print(io, gpa, "ok: removed {s} {s}{s}\n", .{
            cfg.rest[1],
            cfg.rest[2],
            if (change == .noop) " (already absent)" else "",
        });
        return;
    }

    if (std.mem.eql(u8, action, "up") or std.mem.eql(u8, action, "down")) {
        if (cfg.rest.len != 2) {
            try usage(io);
            std.process.exit(2);
        }
        const up = std.mem.eql(u8, action, "up");
        const change = host.ifaceSetUp(cfg.rest[1], up) catch |err| {
            try reportHostError(io, gpa, "iface link", err);
            std.process.exit(1);
        };
        try print(io, gpa, "ok: {s} {s}{s}\n", .{
            cfg.rest[1],
            action,
            if (change == .noop) " (already there)" else "",
        });
        return;
    }

    try usage(io);
    std.process.exit(2);
}

fn routeCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len < 2) {
        try usage(io);
        std.process.exit(2);
    }

    const action = cfg.rest[0];
    const add = std.mem.eql(u8, action, "add");
    if (!add and !std.mem.eql(u8, action, "del")) {
        try usage(io);
        std.process.exit(2);
    }

    var dst: ?[]const u8 = null;
    var via: ?[]const u8 = null;
    var dev: ?[]const u8 = null;
    var metric: u32 = 0;
    var table: u32 = 0;

    var i: usize = 1;
    while (i < cfg.rest.len) : (i += 1) {
        const arg = cfg.rest[i];
        if (std.mem.eql(u8, arg, "via") or
            std.mem.eql(u8, arg, "dev") or
            std.mem.eql(u8, arg, "metric") or
            std.mem.eql(u8, arg, "table"))
        {
            if (i + 1 >= cfg.rest.len) {
                try usage(io);
                std.process.exit(2);
            }
            i += 1;
            const value = cfg.rest[i];
            if (std.mem.eql(u8, arg, "via")) {
                via = value;
            } else if (std.mem.eql(u8, arg, "dev")) {
                dev = value;
            } else if (std.mem.eql(u8, arg, "metric")) {
                metric = std.fmt.parseInt(u32, value, 10) catch {
                    try printErr(io, gpa, "invalid metric '{s}'\n", .{value});
                    std.process.exit(2);
                };
            } else {
                table = std.fmt.parseInt(u32, value, 10) catch {
                    try printErr(io, gpa, "invalid table '{s}'\n", .{value});
                    std.process.exit(2);
                };
            }
            continue;
        }

        if (dst == null) {
            dst = arg;
            continue;
        }

        try usage(io);
        std.process.exit(2);
    }

    const dst_text = dst orelse {
        try usage(io);
        std.process.exit(2);
    };
    const dev_text = dev orelse {
        try usage(io);
        std.process.exit(2);
    };

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    var host = openHost(init, &parsed) catch |err| {
        try reportHostError(io, gpa, "state", err);
        std.process.exit(1);
    };
    defer host.deinit();

    const change = if (add)
        host.routeAdd(dst_text, via, dev_text, metric, table) catch |err| {
            if (err == error.Busy) {
                try printErr(io, gpa, "vnat: route add: route already exists and is not managed by vnat\n", .{});
                std.process.exit(1);
            }
            try reportHostError(io, gpa, "route add", err);
            std.process.exit(1);
        }
    else
        host.routeDel(dst_text, via, dev_text, metric, table) catch |err| {
            try reportHostError(io, gpa, "route del", err);
            std.process.exit(1);
        };

    try print(io, gpa, "ok: route {s} {s} via {s} dev {s} metric {d} table {d}{s}\n", .{
        action,
        dst_text,
        via orelse "-",
        dev_text,
        metric,
        table,
        if (change == .noop) " (already configured)" else "",
    });
}

fn downCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len != 0) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    var host = openHost(init, &parsed) catch |err| {
        try reportHostError(io, gpa, "state", err);
        std.process.exit(1);
    };
    defer host.deinit();

    const result = host.down() catch |err| {
        try reportHostError(io, gpa, "down", err);
        std.process.exit(1);
    };

    if (result.failed != 0) {
        try printErr(io, gpa, "vnat: restored {d}, failed {d}; journal retained\n", .{
            result.restored,
            result.failed,
        });
        std.process.exit(1);
    }

    if (result.restored == 0) {
        try print(io, gpa, "ok: no journaled state\n", .{});
    } else {
        try print(io, gpa, "ok: restored {d} operation(s)\n", .{result.restored});
    }
}

fn journalCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len != 0) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    var host = openHost(init, &parsed) catch |err| {
        try reportHostError(io, gpa, "state", err);
        std.process.exit(1);
    };
    defer host.deinit();

    const contents_opt = host.journalContents() catch |err| {
        try reportHostError(io, gpa, "journal", err);
        std.process.exit(1);
    };
    const contents = contents_opt orelse {
        try print(io, gpa, "no journal\n", .{});
        return;
    };
    defer gpa.free(contents);
    try std.Io.File.stdout().writeStreamingAll(io, contents);
}

fn configPath(args: []const []const u8) ![]const u8 {
    if (args.len == 1 and !std.mem.startsWith(u8, args[0], "-")) return args[0];
    if (args.len == 2 and
        (std.mem.eql(u8, args[0], "-c") or std.mem.eql(u8, args[0], "--config")))
    {
        return args[1];
    }
    return error.InvalidArgument;
}

fn validateFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !u8 {
    const source = readConfig(io, gpa, path) catch |err| {
        try printErr(io, gpa, "cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer gpa.free(source);

    var parsed = vnat.config_parse.parse(gpa, source) catch |err| {
        try printErr(io, gpa, "{s}: invalid config: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer parsed.deinit();

    vnat.config_validate.validate(&parsed.config) catch |err| {
        try printErr(io, gpa, "{s}: invalid config: {s}\n", .{ path, @errorName(err) });
        return 1;
    };

    try print(io, gpa, "ok: {s} (ports={d}, bridges={d}, interfaces={d})\n", .{
        parsed.config.instance,
        parsed.config.ports.count(),
        parsed.config.bridges.count(),
        parsed.config.interfaces.count(),
    });
    return 0;
}

fn statusFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !u8 {
    const source = readConfig(io, gpa, path) catch |err| {
        try printErr(io, gpa, "cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer gpa.free(source);

    var parsed = vnat.config_parse.parse(gpa, source) catch |err| {
        try printErr(io, gpa, "{s}: invalid config: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer parsed.deinit();

    vnat.config_validate.validate(&parsed.config) catch |err| {
        try printErr(io, gpa, "{s}: invalid config: {s}\n", .{ path, @errorName(err) });
        return 1;
    };

    var manager = vnat.manager.Manager.openFromConfig(gpa, io, &parsed.config) catch |err| {
        try printErr(io, gpa, "open ports: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer manager.deinit(io);

    manager.refreshAll(io) catch |err| {
        try printErr(io, gpa, "refresh ports: {s}\n", .{@errorName(err)});
        return 1;
    };

    try print(io, gpa, "instance: {s}\n", .{parsed.config.instance});
    try print(io, gpa, "{s:<12} {s:<12} {s:>7} {s:>5} {s:<4} {s:>10} {s:>10} {s:>6}\n", .{
        "PORT", "DEVICE", "IFINDEX", "MTU", "LINK", "RX", "TX", "DROP",
    });
    for (0..manager.count()) |i| {
        const entry = manager.entryAt(i).?;
        const info = entry.port.info();
        const stats = entry.port.stats();
        try print(io, gpa, "{s:<12} {s:<12} {d:>7} {d:>5} {s:<4} {d:>10} {d:>10} {d:>6}\n", .{
            entry.config_name,
            info.name,
            info.ifindex,
            info.mtu,
            @tagName(info.link),
            stats.rx_packets,
            stats.tx_packets,
            stats.drops,
        });
    }
    return 0;
}

fn bridgeCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len != 1 or !std.mem.eql(u8, cfg.rest[0], "list")) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();
    const config = &parsed.config;

    try print(io, gpa, "BRIDGE       VLAN STP OFFLOAD MEMBERS SVIS\n", .{});
    var it = config.bridges.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const bridge = entry.value_ptr.*;
        var svi_count: usize = 0;
        var iface_it = config.interfaces.iterator();
        while (iface_it.next()) |iface_entry| {
            if (iface_entry.value_ptr.bridge) |bridge_name| {
                if (std.mem.eql(u8, bridge_name, name)) svi_count += 1;
            }
        }
        try print(io, gpa, "{s:<12} {s:<4} {s:<3} {s:<7} {d:>7} {d:>4}\n", .{
            name,
            if (bridge.vlan_aware) "yes" else "no",
            if (bridge.stp) "on" else "off",
            @tagName(bridge.offload),
            bridge.ports.len,
            svi_count,
        });
        for (bridge.ports) |port_name| {
            const port = config.ports.get(port_name) orelse continue;
            const pvid: ?u16 = port.pvid orelse
                if (bridge.vlan_aware) 1 else null;
            try print(io, gpa, "  port {s:<10} pvid=", .{port_name});
            if (pvid) |vlan| {
                try print(io, gpa, "{d}", .{vlan});
            } else {
                try print(io, gpa, "-", .{});
            }
            try print(io, gpa, " tagged=", .{});
            if (port.tagged.len == 0) {
                try print(io, gpa, "-\n", .{});
            } else {
                for (port.tagged, 0..) |vlan, i| {
                    if (i != 0) try print(io, gpa, ",", .{});
                    try print(io, gpa, "{d}", .{vlan});
                }
                try print(io, gpa, "\n", .{});
            }
        }
        iface_it = config.interfaces.iterator();
        while (iface_it.next()) |iface_entry| {
            const iface_name = iface_entry.key_ptr.*;
            const iface = iface_entry.value_ptr.*;
            if (iface.bridge) |bridge_name| {
                if (!std.mem.eql(u8, bridge_name, name)) continue;
                try print(io, gpa, "  svi {s:<11} vlan={d} address={s}\n", .{
                    iface_name,
                    iface.vlan orelse 1,
                    iface.address orelse "-",
                });
            }
        }
    }
}

fn portList(io: std.Io, gpa: std.mem.Allocator) !u8 {
    const links = vnat.linux_ports.netlink.listLinks(io, gpa) catch |err| {
        try printErr(io, gpa, "netlink: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer gpa.free(links);

    try print(io, gpa, "{s:<16} {s:>6} {s:>6}  {s:<17}  {s}\n", .{
        "NAME", "INDEX", "MTU", "MAC", "STATE",
    });

    for (links) |*link| {
        var mac_buf: [17]u8 = undefined;
        const mac = std.fmt.bufPrint(&mac_buf, "{f}", .{link.mac}) catch "??";
        try print(io, gpa, "{s:<16} {d:>6} {d:>6}  {s:<17}  {s}\n", .{
            link.name(),
            link.index,
            link.mtu,
            mac,
            if (link.up) "up" else "down",
        });
    }
    return 0;
}

fn selfTest(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8) !u8 {
    if (args.len == 0) {
        try printErr(io, gpa, "usage: vnat selftest l2 <inject> <port-a> <port-b> <recv>\n", .{});
        return 2;
    }

    if (std.mem.eql(u8, args[0], "l2")) {
        if (args.len != 5) {
            try printErr(io, gpa, "usage: vnat selftest l2 <inject> <port-a> <port-b> <recv>\n", .{});
            return 2;
        }
        selfTestL2(io, gpa, args[1..5]) catch |err| {
            try printErr(io, gpa, "selftest l2 failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        return 0;
    }

    if (std.mem.eql(u8, args[0], "tun") or std.mem.eql(u8, args[0], "tap")) {
        if (args.len != 2) {
            try printErr(io, gpa, "usage: vnat selftest tun|tap <name>\n", .{});
            return 2;
        }
        const tap = std.mem.eql(u8, args[0], "tap");
        selfTestTun(io, gpa, args[1], tap) catch |err| {
            try printErr(io, gpa, "selftest {s} failed: {s}\n", .{ args[0], @errorName(err) });
            return 1;
        };
        return 0;
    }

    try printErr(io, gpa, "unknown selftest '{s}'\n", .{args[0]});
    return 2;
}

fn selfTestL2(io: std.Io, gpa: std.mem.Allocator, names: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const af = vnat.linux_ports.af_packet;
    const inject = try af.AfPacketPort.open(a, io, .{ .value = 1 }, .{ .name = names[0] });
    defer inject.port().deinit(io);
    const in_port = try af.AfPacketPort.open(a, io, .{ .value = 2 }, .{ .name = names[1] });
    defer in_port.port().deinit(io);
    const out_port = try af.AfPacketPort.open(a, io, .{ .value = 3 }, .{ .name = names[2] });
    defer out_port.port().deinit(io);
    const recv = try af.AfPacketPort.open(a, io, .{ .value = 4 }, .{ .name = names[3] });
    defer recv.port().deinit(io);

    const frame_hex =
        "ffffffffffff00112233445508004500001c00010000401100000a0000010a000002" ++
        "04d2162e00080000";
    const payload_len = 42;
    var frame: [60]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(frame[0..payload_len], frame_hex);

    try inject.port().write(io, &frame);

    var buf: [2048]u8 = undefined;
    const first_len = try readMatching(io, in_port.port(), &buf, frame[0..payload_len], 2000);
    try out_port.port().write(io, buf[0..first_len]);
    _ = try readMatching(io, recv.port(), &buf, frame[0..payload_len], 2000);

    try print(io, gpa, "ok: l2 forwarding {s} -> {s} -> {s} -> {s}\n", .{
        names[0], names[1], names[2], names[3],
    });
}

fn selfTestTun(io: std.Io, gpa: std.mem.Allocator, name: []const u8, tap: bool) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const tun = vnat.linux_ports.tun;
    const p = try tun.TunPort.open(arena.allocator(), io, .{ .value = 1 }, .{
        .name = name,
        .tap = tap,
        .mtu = 1400,
    });
    defer p.port().deinit(io);

    const info = p.port().info();
    if (info.ifindex == 0 or info.mtu != 1400) return error.SelftestFailed;

    try print(io, gpa, "ok: {s} {s} ifindex={d} mtu={d}\n", .{
        @tagName(info.kind),
        info.name,
        info.ifindex,
        info.mtu,
    });
}

/// Reads frames until one starts with `expected` (the veth pair may carry
/// unrelated IPv6/ND traffic). Returns the matching frame length.
fn readMatching(
    io: std.Io,
    port: vnat.Port,
    buf: []u8,
    expected: []const u8,
    timeout_ms: u64,
) !usize {
    var elapsed: u64 = 0;
    while (elapsed <= timeout_ms) : (elapsed += 1) {
        if (try port.read(io, buf)) |n| {
            if (n >= expected.len and std.mem.eql(u8, buf[0..expected.len], expected)) {
                return n;
            }
        }
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

fn readConfig(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes));
}

fn firewallCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len == 0) {
        try usage(io);
        std.process.exit(2);
    }
    if (std.mem.eql(u8, cfg.rest[0], "test")) {
        try firewallTest(init, cfg.path, cfg.rest[1..]);
        return;
    }
    if (std.mem.eql(u8, cfg.rest[0], "counters")) {
        if (cfg.rest.len != 1) {
            try usage(io);
            std.process.exit(2);
        }
        try firewallCounters(init, cfg.path);
        return;
    }
    if (cfg.rest.len != 1 or !std.mem.eql(u8, cfg.rest[0], "list")) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    const firewall = &parsed.config.firewall;
    try print(io, gpa, "defaults: in={s} forward={s} out={s} rp_filter={s}\n", .{
        @tagName(firewall.default_in),
        @tagName(firewall.default_forward),
        @tagName(firewall.default_out),
        if (firewall.rp_filter) "on" else "off",
    });
    try print(io, gpa, "rate-limit: icmp={d}/s arp={d}/s dhcp={d}/s\n", .{
        firewall.rate_limit.icmp,
        firewall.rate_limit.arp,
        firewall.rate_limit.dhcp,
    });
    for (firewall.rules, 0..) |rule, i| {
        try print(io, gpa, "{d}: {s}", .{ i + 1, @tagName(rule.action) });
        if (rule.proto) |proto| try print(io, gpa, " proto={s}", .{@tagName(proto)});
        if (rule.src) |src| try print(io, gpa, " src={s}", .{src});
        if (rule.dst) |dst| try print(io, gpa, " dst={s}", .{dst});
        if (rule.sport) |port| try print(io, gpa, " sport={d}", .{port});
        if (rule.dport) |port| try print(io, gpa, " dport={d}", .{port});
        if (rule.iif) |iif| try print(io, gpa, " iif={s}", .{iif});
        if (rule.oif) |oif| try print(io, gpa, " oif={s}", .{oif});
        if (rule.ct_state.len > 0) {
            try print(io, gpa, " ct_state=", .{});
            for (rule.ct_state, 0..) |state, j| {
                if (j > 0) try print(io, gpa, ",", .{});
                try print(io, gpa, "{s}", .{@tagName(state)});
            }
        }
        try print(io, gpa, "\n", .{});
    }
}

fn firewallCounters(init: std.process.Init, path: []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;

    var parsed = loadConfig(io, gpa, path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    var loaded = vnat.firewall_counters.load(
        io,
        gpa,
        stateDir(init),
        parsed.config.instance,
    ) catch |err| {
        try printErr(io, gpa, "cannot read firewall counters: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    } orelse {
        try printErr(io, gpa, "no firewall counters for {s} (is vnatd running?)\n", .{
            parsed.config.instance,
        });
        std.process.exit(1);
    };
    defer loaded.deinit();

    const value = &loaded.value;
    const now_ms = std.Io.Clock.now(.real, io).toMilliseconds();
    const age_ms = @max(@as(i64, 0), now_ms - value.updated_ms);
    try print(io, gpa, "instance: {s}\nupdated: {d}ms ago\n", .{
        value.instance,
        age_ms,
    });
    for (value.rules, 0..) |packets, i| {
        try print(io, gpa, "rule {d}: {d} packets\n", .{ i + 1, packets });
    }
    try print(
        io,
        gpa,
        "policy: dropped={d} spoofed={d} rate-limit={d}/{d}/{d}\n",
        .{
            value.firewall_dropped,
            value.firewall_spoofed,
            value.icmp_rate_limited,
            value.arp_rate_limited,
            value.dhcp_rate_limited,
        },
    );
}

fn firewallTest(init: std.process.Init, path: []const u8, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;

    var proto: ?u8 = null;
    var src: ?vnat.types.Ipv4 = null;
    var dst: ?vnat.types.Ipv4 = null;
    var sport: ?u16 = null;
    var dport: ?u16 = null;
    var iif: ?[]const u8 = null;
    var oif: ?[]const u8 = null;
    var state: vnat.config_schema.FirewallCtState = .new;
    var hook: vnat.forward.Forwarder.FirewallHook = .forward;

    var i: usize = 0;
    while (i < args.len) {
        const flag = args[i];
        if (std.mem.eql(u8, flag, "--help")) {
            try usage(io);
            return;
        }
        if (i + 1 >= args.len) {
            try printErr(io, gpa, "vnat: firewall test: missing value for {s}\n", .{flag});
            std.process.exit(2);
        }
        const value = args[i + 1];
        if (std.mem.eql(u8, flag, "--proto")) {
            proto = parseProto(value) orelse {
                try printErr(io, gpa, "vnat: firewall test: invalid protocol '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--src")) {
            src = vnat.types.Ipv4.parse(value) catch {
                try printErr(io, gpa, "vnat: firewall test: invalid source '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--dst")) {
            dst = vnat.types.Ipv4.parse(value) catch {
                try printErr(io, gpa, "vnat: firewall test: invalid destination '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--sport")) {
            sport = parsePort(value) orelse {
                try printErr(io, gpa, "vnat: firewall test: invalid source port '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--dport")) {
            dport = parsePort(value) orelse {
                try printErr(io, gpa, "vnat: firewall test: invalid destination port '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--iif")) {
            iif = value;
        } else if (std.mem.eql(u8, flag, "--oif")) {
            oif = value;
        } else if (std.mem.eql(u8, flag, "--state")) {
            state = parseCtState(value) orelse {
                try printErr(io, gpa, "vnat: firewall test: invalid state '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, flag, "--hook")) {
            hook = parseHook(value) orelse {
                try printErr(io, gpa, "vnat: firewall test: invalid hook '{s}'\n", .{value});
                std.process.exit(2);
            };
        } else {
            try printErr(io, gpa, "vnat: firewall test: unknown option '{s}'\n", .{flag});
            std.process.exit(2);
        }
        i += 2;
    }

    if (proto == null or src == null or dst == null) {
        try printErr(io, gpa, "vnat: firewall test requires --proto, --src and --dst\n", .{});
        std.process.exit(2);
    }
    if ((sport != null or dport != null) and proto != 6 and proto != 17) {
        try printErr(io, gpa, "vnat: firewall test: ports require --proto tcp|udp\n", .{});
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    const result = vnat.forward.Forwarder.probeFirewallConfig(
        gpa,
        io,
        &parsed.config,
        .{
            .proto = proto.?,
            .src = src.?,
            .dst = dst.?,
            .sport = sport,
            .dport = dport,
            .iif = iif,
            .oif = oif,
            .state = state,
            .hook = hook,
        },
    ) catch |err| {
        try printErr(io, gpa, "vnat: firewall test: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    if (result.rule) |index| {
        try print(io, gpa, "rule {d}: {s}\n", .{ index + 1, @tagName(result.action) });
    } else {
        try print(io, gpa, "default: {s}\n", .{@tagName(result.action)});
    }
}

fn parseProto(text: []const u8) ?u8 {
    if (std.mem.eql(u8, text, "tcp")) return 6;
    if (std.mem.eql(u8, text, "udp")) return 17;
    if (std.mem.eql(u8, text, "icmp")) return 1;
    return null;
}

fn parsePort(text: []const u8) ?u16 {
    const value = std.fmt.parseInt(u16, text, 10) catch return null;
    if (value == 0) return null;
    return value;
}

fn parseCtState(text: []const u8) ?vnat.config_schema.FirewallCtState {
    if (std.mem.eql(u8, text, "new")) return .new;
    if (std.mem.eql(u8, text, "established")) return .established;
    if (std.mem.eql(u8, text, "related")) return .related;
    if (std.mem.eql(u8, text, "invalid")) return .invalid;
    return null;
}

fn parseHook(text: []const u8) ?vnat.forward.Forwarder.FirewallHook {
    if (std.mem.eql(u8, text, "input")) return .input;
    if (std.mem.eql(u8, text, "forward")) return .forward;
    if (std.mem.eql(u8, text, "output")) return .output;
    return null;
}

fn dhcpCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len < 1 or !std.mem.eql(u8, cfg.rest[0], "status")) {
        try usage(io);
        std.process.exit(2);
    }

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    const db_path = parsed.config.lease_db orelse {
        try print(io, gpa, "no lease database configured\n", .{});
        return;
    };

    const data = std.Io.Dir.cwd().readFileAlloc(io, db_path, gpa, .limited(8 * 1024 * 1024)) catch |err| {
        try printErr(io, gpa, "cannot read {s}: {s}\n", .{ db_path, @errorName(err) });
        std.process.exit(1);
    };
    defer gpa.free(data);

    var parsed_db = std.json.parseFromSlice(DhcpLeaseDbWire, gpa, data, .{}) catch |err| {
        try printErr(io, gpa, "invalid lease db {s}: {s}\n", .{ db_path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed_db.deinit();

    if (parsed_db.value.leases.len == 0) {
        try print(io, gpa, "no leases\n", .{});
        return;
    }
    for (parsed_db.value.leases) |lease| {
        try print(io, gpa, "{s} port={d} mac={s} state={s} expires_ms={d}\n", .{
            lease.ip,
            lease.port,
            lease.mac,
            lease.state,
            lease.expires_ms,
        });
    }
}

fn dnsCommand(init: std.process.Init, args: []const []const u8) !void {
    const io = init.io;
    const gpa = init.gpa;
    const cfg = splitConfig(args);
    if (cfg.rest.len < 2 or !std.mem.eql(u8, cfg.rest[0], "query")) {
        try usage(io);
        std.process.exit(2);
    }
    const name = cfg.rest[1];

    var parsed = loadConfig(io, gpa, cfg.path) catch |err| {
        try printErr(io, gpa, "cannot load {s}: {s}\n", .{ cfg.path, @errorName(err) });
        std.process.exit(1);
    };
    defer parsed.deinit();

    const listen_text = parsed.config.dns.listen orelse "127.0.0.1";
    const listen_ip = vnat.types.Ipv4.parse(listen_text) catch {
        try printErr(io, gpa, "invalid dns listen address\n", .{});
        std.process.exit(1);
    };

    var qbuf: [512]u8 = undefined;
    @memset(qbuf[0..12], 0);
    std.mem.writeInt(u16, qbuf[0..2], 0x1234, .big);
    std.mem.writeInt(u16, qbuf[4..6], 1, .big);
    var pos: usize = 12;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        if (pos + 1 + label.len + 4 > qbuf.len) {
            try printErr(io, gpa, "name too long\n", .{});
            std.process.exit(1);
        }
        qbuf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(qbuf[pos..][0..label.len], label);
        pos += label.len;
    }
    qbuf[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, qbuf[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, qbuf[pos..][0..2], 1, .big);
    pos += 2;
    const query = qbuf[0..pos];

    const dest = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = listen_ip.toBytes(),
        .port = 53,
    } };
    const local = std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
    var sock = local.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        try printErr(io, gpa, "bind: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer sock.close(io);
    sock.send(io, &dest, query) catch |err| {
        try printErr(io, gpa, "send: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };

    var rbuf: [512]u8 = undefined;
    const timeout = std.Io.Timeout{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(5000),
        .clock = .awake,
    } };
    const incoming = sock.receiveTimeout(io, &rbuf, timeout) catch |err| {
        try printErr(io, gpa, "receive: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    const data = incoming.data;

    if (data.len < 12) {
        try printErr(io, gpa, "short response\n", .{});
        std.process.exit(1);
    }
    const ancount = std.mem.readInt(u16, data[6..8], .big);
    if (ancount == 0) {
        try print(io, gpa, "no answer\n", .{});
        return;
    }

    // Skip header and question.
    var i: usize = 12;
    while (i < data.len and data[i] != 0) : (i += 1 + data[i]) {}
    i += 5; // null + qtype + qclass
    if (i + 12 > data.len) {
        try printErr(io, gpa, "truncated response\n", .{});
        std.process.exit(1);
    }
    // Answer: name(2) type(2) class(2) ttl(4) rdlen(2) rdata
    i += 2; // skip name pointer
    const rtype = std.mem.readInt(u16, data[i..][0..2], .big);
    i += 2;
    i += 2; // class
    const ttl = std.mem.readInt(u32, data[i..][0..4], .big);
    i += 4;
    const rdlen = std.mem.readInt(u16, data[i..][0..2], .big);
    i += 2;
    if (rtype == 1 and rdlen == 4 and i + 4 <= data.len) {
        try print(io, gpa, "{d}.{d}.{d}.{d} (ttl={d})\n", .{
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            ttl,
        });
    } else {
        try print(io, gpa, "non-A answer\n", .{});
    }
}

fn usage(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\vnat — portable virtual router
        \\
        \\Usage:
        \\  vnat version
        \\  vnat validate <config.json>
        \\  vnat port list
        \\  vnat status [-c] <config.json>
        \\  vnat iface set|del <dev> <cidr> [-c <config>]
        \\  vnat iface up|down <dev> [-c <config>]
        \\  vnat route add|del <dst> [via <ip>] dev <dev> [metric <n>] [table <n>] [-c <config>]
        \\  vnat down [-c <config>]
        \\  vnat journal [-c <config>]
        \\  vnat bridge list [-c <config>]
        \\  vnat firewall list [-c <config>]
        \\  vnat firewall counters [-c <config>]
        \\  vnat firewall test --proto tcp|udp|icmp --src <ip> --dst <ip> [--sport <n>] [--dport <n>] [--iif <name>] [--oif <name>] [--state new|established|related|invalid] [--hook input|forward|output] [-c <config>]
        \\  vnat selftest l2 <inject> <port-a> <port-b> <recv>
        \\  vnat selftest tun|tap <name>
        \\  vnat help
        \\
        \\Host mutations are journaled under $VNAT_RUN_DIR (default /run/vnat).
        \\
    );
}

fn print(io: std.Io, gpa: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    try buf.writer.print(fmt, args);
    try std.Io.File.stdout().writeStreamingAll(io, buf.written());
}

fn printErr(io: std.Io, gpa: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    var buf: std.Io.Writer.Allocating = .init(gpa);
    defer buf.deinit();
    try buf.writer.print(fmt, args);
    try std.Io.File.stderr().writeStreamingAll(io, buf.written());
}
