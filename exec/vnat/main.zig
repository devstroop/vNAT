const std = @import("std");
const vnat = @import("vnat");

const max_config_bytes = 4 * 1024 * 1024;
const default_config = "/etc/vnat/vnat.json";

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
    var frame: [60]u8 = [_]u8{0} ** 60;
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
