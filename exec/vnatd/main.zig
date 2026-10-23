const std = @import("std");
const vnat = @import("vnat");

const max_config_bytes = 4 * 1024 * 1024;
const default_config = "/etc/vnat/vnat.json";

var stop = std.atomic.Value(bool).init(false);

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    stop.store(true, .release);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "vnatd: {s}\n", .{@errorName(err)}) catch "vnatd: error\n";
        std.Io.File.stderr().writeStreamingAll(init.io, msg) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var path: []const u8 = default_config;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try usage(io);
            return;
        }
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            path = args[i];
            continue;
        }
        return error.InvalidArgument;
    }

    const source = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(max_config_bytes),
    );
    defer gpa.free(source);

    var parsed = try vnat.config_parse.parse(gpa, source);
    defer parsed.deinit();
    try vnat.config_validate.validate(&parsed.config);

    var logger = vnat.log.Logger.init(io, parsed.config.log);

    var manager = try vnat.manager.Manager.openFromConfig(gpa, io, &parsed.config);
    defer manager.deinit(io);
    try manager.enableMonitor();
    try manager.refreshAll(io);

    const port_entries = try gpa.alloc(vnat.forward.PortEntry, manager.count());
    defer gpa.free(port_entries);
    for (manager.entries, 0..) |entry, idx| {
        port_entries[idx] = .{
            .id = entry.port.info().id,
            .config_name = entry.config_name,
            .port = entry.port,
        };
    }

    var forwarder = try vnat.forward.Forwarder.fromConfig(gpa, &parsed.config, port_entries);
    defer forwarder.deinit();

    const action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);

    try forwarder.announce(io);

    logger.info("started instance={s} ports={d} local={d} routes={d}", .{
        parsed.config.instance,
        manager.count(),
        forwarder.local.items.len,
        forwarder.fib.count(),
    });

    var buf: [2048]u8 = undefined;
    var netlink_tick: u8 = 0;
    while (!stop.load(.acquire)) {
        forwarder.tick(io);
        netlink_tick +%= 1;
        if (netlink_tick >= 100) {
            netlink_tick = 0;
            const event = manager.poll(io) catch |err| blk: {
                logger.warn("netlink: {s}", .{@errorName(err)});
                break :blk null;
            };
            if (event) |ev| logEvent(&logger, &ev);
        }

        var did_work = false;
        for (port_entries) |entry| {
            var budget: usize = 0;
            while (budget < 64) : (budget += 1) {
                const maybe_frame = entry.port.read(io, &buf) catch |err| {
                    logger.debug("read {s}: {s}", .{ entry.config_name, @errorName(err) });
                    break;
                };
                if (maybe_frame == null) break;
                did_work = true;
                forwarder.handle(io, buf[0..maybe_frame.?], entry.id) catch |err| {
                    logger.debug("forward {s}: {s}", .{ entry.config_name, @errorName(err) });
                };
            }
        }

        if (!did_work) {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
        }
    }

    logger.info(
        "stopping instance={s} forwarded={d} dropped={d} pending={d}/{d} ct={d}/{d} snat={d}",
        .{
            parsed.config.instance,
            forwarder.counters.forwarded,
            forwarder.counters.dropped,
            forwarder.counters.pending_queued,
            forwarder.counters.pending_flushed,
            forwarder.conntrack.counters.created,
            forwarder.conntrack.counters.hits,
            forwarder.counters.snat_packets,
        },
    );
}

fn logEvent(logger: *const vnat.log.Logger, event: *const vnat.linux_ports.netlink.Event) void {
    switch (event.kind) {
        .link => logger.info("link {s} index={d} name={s} up={}", .{
            @tagName(event.action),
            event.index,
            event.name(),
            event.up,
        }),
        .addr => logger.info("addr {s} index={d} family={d} prefix={d}", .{
            @tagName(event.action),
            event.index,
            event.family,
            event.prefix_len,
        }),
        .neigh => logger.info("neigh {s} index={d} family={d}", .{
            @tagName(event.action),
            event.index,
            event.family,
        }),
    }
}

fn usage(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\vnatd — vNAT daemon
        \\
        \\Usage:
        \\  vnatd [-c <config.json>]
        \\
        \\Defaults to /etc/vnat/vnat.json. Stops on SIGINT or SIGTERM.
        \\
    );
}
