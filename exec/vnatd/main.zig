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

    const run_dir = init.environ_map.get("VNAT_RUN_DIR") orelse "/run/vnat";
    var host: ?vnat.control_host.Host = null;
    defer if (host) |*h| h.deinit();
    var offload_checkpoint: usize = 0;
    if (vnat.control_offload.isEnabled(&parsed.config)) {
        host = try vnat.control_host.Host.init(
            io,
            gpa,
            run_dir,
            parsed.config.instance,
        );
        offload_checkpoint = try host.?.checkpoint();
    }
    errdefer if (host) |*h| {
        _ = h.downTo(offload_checkpoint) catch {};
    };

    var offload_plan = vnat.control_offload.Plan.init(gpa);
    defer offload_plan.deinit();
    if (host) |*h| {
        offload_plan = vnat.control_offload.apply(io, gpa, h, &parsed.config) catch |err| {
            logger.err("kernel offload: {s}; run `vnat down -c <config>` to repair", .{
                @errorName(err),
            });
            return err;
        };
        for (offload_plan.devices) |device| {
            logger.info("offload bridge={s} kernel={s} trunk={s}", .{
                device.bridge_name,
                device.kernel_bridge,
                device.veth_vnat,
            });
        }
        for (offload_plan.skipped) |port_name| {
            const port = parsed.config.ports.get(port_name) orelse continue;
            if (port.storm_control != 0) {
                logger.warn(
                    "kernel offload: storm_control is not enforced on offloaded members; set it to 0 to silence this warning",
                    .{},
                );
                break;
            }
        }
    }

    const extras = try gpa.alloc(vnat.manager.ExtraPort, offload_plan.synthetic.len);
    defer gpa.free(extras);
    for (offload_plan.synthetic, 0..) |synthetic, index| {
        extras[index] = .{
            .config_name = synthetic.config_name,
            .device = synthetic.device,
        };
    }

    var manager = try vnat.manager.Manager.openFromConfigWithOptions(gpa, io, &parsed.config, .{
        .skip = offload_plan.skipped,
        .extras = extras,
    });
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

    var forwarder = try vnat.forward.Forwarder.fromConfig(gpa, io, &parsed.config, port_entries);
    defer forwarder.deinit();

    const counter_packets = try gpa.alloc(u64, forwarder.firewallRuleCount());
    defer gpa.free(counter_packets);
    var counter_save_ms = nowMs(io);
    var counter_warned = false;

    var lease_store: ?vnat.dhcp_leases.Store = null;
    defer if (lease_store) |*store| store.deinit();
    if (parsed.config.lease_db) |db_path| {
        lease_store = vnat.dhcp_leases.Store.init(gpa, io, db_path) catch |err| {
            logger.err("lease db {s}: {s}", .{ db_path, @errorName(err) });
            return err;
        };
        const restored = lease_store.?.load(forwarder.dhcpServers(), nowMs(io)) catch |err| {
            logger.err("lease db {s}: {s}", .{ db_path, @errorName(err) });
            return err;
        };
        if (restored != 0) {
            logger.info("dhcp leases restored={d} db={s}", .{ restored, db_path });
        }
    }

    var upstreams: ?[]vnat.types.Ipv4 = null;
    defer if (upstreams) |items| gpa.free(items);
    var dns_zones: ?[]vnat.dns_service.Zone = null;
    defer if (dns_zones) |zones| {
        for (zones) |zone| gpa.free(zone.upstreams);
        gpa.free(zones);
    };
    var dns_service: ?vnat.dns_service.Service = null;
    defer if (dns_service) |*service| service.deinit();
    if (parsed.config.dns.upstreams.len != 0 or parsed.config.dns.zones.len != 0) {
        const items = try gpa.alloc(vnat.types.Ipv4, parsed.config.dns.upstreams.len);
        upstreams = items;
        for (parsed.config.dns.upstreams, 0..) |text, upstream_index| {
            items[upstream_index] = vnat.types.Ipv4.parse(text) catch return error.InvalidArgument;
        }
        if (parsed.config.dns.zones.len != 0) {
            const zones = try gpa.alloc(vnat.dns_service.Zone, parsed.config.dns.zones.len);
            dns_zones = zones;
            for (parsed.config.dns.zones, 0..) |zone_cfg, zone_index| {
                const zone_upstreams = try gpa.alloc(vnat.types.Ipv4, zone_cfg.upstreams.len);
                for (zone_cfg.upstreams, 0..) |text, upstream_index| {
                    zone_upstreams[upstream_index] = vnat.types.Ipv4.parse(text) catch return error.InvalidArgument;
                }
                zones[zone_index] = .{
                    .suffix = zone_cfg.suffix,
                    .upstreams = zone_upstreams,
                };
            }
        }
        const listen = vnat.types.Ipv4.parse(parsed.config.dns.listen orelse
            return error.InvalidArgument) catch return error.InvalidArgument;
        dns_service = vnat.dns_service.Service.init(io, gpa, .{
            .listen_ip = listen,
            .upstreams = items,
            .cache = parsed.config.dns.cache,
            .cache_max_entries = parsed.config.dns.max_entries,
            .tcp = parsed.config.dns.tcp,
            .zones = if (dns_zones) |zones| zones else &.{},
        }) catch |err| {
            logger.err(
                "dns listen={f}: {s}; assign the address first with `vnat iface set <dev> <cidr>`",
                .{ listen, @errorName(err) },
            );
            return err;
        };
        try dns_service.?.start();
        logger.info("dns listening={f} upstreams={d} cache={}", .{
            listen,
            items.len,
            parsed.config.dns.cache,
        });
    }

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
    var lease_save_ms = nowMs(io);
    while (!stop.load(.acquire)) {
        forwarder.tick(io);
        const now = nowMs(io);
        if (now - counter_save_ms >= 5_000) {
            saveFirewallCounters(
                io,
                gpa,
                run_dir,
                parsed.config.instance,
                &forwarder,
                counter_packets,
            ) catch |err| {
                if (!counter_warned) {
                    logger.warn("firewall counters {s}: {s}", .{ run_dir, @errorName(err) });
                    counter_warned = true;
                }
            };
            counter_save_ms = now;
        }
        if (lease_store) |*store| {
            if (now - lease_save_ms >= 60_000) {
                store.save(forwarder.dhcpServers()) catch |err| {
                    logger.warn("lease db save: {s}", .{@errorName(err)});
                };
                lease_save_ms = now;
            }
        }
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

    if (lease_store) |*store| {
        store.save(forwarder.dhcpServers()) catch |err| {
            logger.warn("lease db save: {s}", .{@errorName(err)});
        };
    }

    saveFirewallCounters(
        io,
        gpa,
        run_dir,
        parsed.config.instance,
        &forwarder,
        counter_packets,
    ) catch |err| {
        if (!counter_warned) logger.warn("firewall counters {s}: {s}", .{ run_dir, @errorName(err) });
    };

    if (dns_service) |service| {
        logger.info("dns stopping queries={d} responses={d} hits={d} errors={d} dropped={d}", .{
            service.counters.queries.load(.monotonic),
            service.counters.responses.load(.monotonic),
            service.counters.cache_hits.load(.monotonic),
            service.counters.upstream_errors.load(.monotonic),
            service.counters.dropped.load(.monotonic),
        });
    }

    logger.info(
        "stopping instance={s} forwarded={d} bridged={d} dropped={d} fw-drop={d} pending={d}/{d} ct={d}/{d} snat={d} dnat={d} icmp={d} dhcp={d}/{d}/{d} dhcp-client={d} storm-drop={d} rate-limit={d}/{d}/{d} stp={d}/{d}/{d}/{d}",
        .{
            parsed.config.instance,
            forwarder.counters.forwarded,
            forwarder.counters.bridged,
            forwarder.counters.dropped,
            forwarder.counters.firewall_dropped,
            forwarder.counters.pending_queued,
            forwarder.counters.pending_flushed,
            forwarder.conntrack.counters.created,
            forwarder.conntrack.counters.hits,
            forwarder.counters.snat_packets,
            forwarder.counters.dnat_packets,
            forwarder.counters.icmp_translated,
            forwarder.counters.dhcp_offers,
            forwarder.counters.dhcp_acks,
            forwarder.counters.dhcp_requests,
            forwarder.counters.icmp_rate_limited,
            forwarder.counters.arp_rate_limited,
            forwarder.counters.dhcp_rate_limited,
            forwarder.counters.dhcp_client_bound,
            forwarder.counters.storm_dropped,
            forwarder.counters.stp_bpdus_rx,
            forwarder.counters.stp_bpdus_tx,
            forwarder.counters.stp_filtered,
            forwarder.counters.stp_invalid,
        },
    );
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.now(.awake, io).toMilliseconds();
}

fn saveFirewallCounters(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    instance: []const u8,
    forwarder: *const vnat.forward.Forwarder,
    packets: []u64,
) !void {
    const count = forwarder.snapshotFirewallPackets(packets);
    try vnat.firewall_counters.save(io, gpa, state_dir, instance, packets[0..count], .{
        .firewall_dropped = forwarder.counters.firewall_dropped,
        .firewall_spoofed = forwarder.counters.firewall_spoofed,
        .icmp_rate_limited = forwarder.counters.icmp_rate_limited,
        .arp_rate_limited = forwarder.counters.arp_rate_limited,
        .dhcp_rate_limited = forwarder.counters.dhcp_rate_limited,
    });
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
