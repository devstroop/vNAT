//! Reusable vRouter runtime lifecycle shared by `vrouterd` and the C ABI.

const std = @import("std");
const schema = @import("../config/schema.zig");
const types = @import("../types.zig");
const log = @import("../log.zig");
const manager_mod = @import("../port/manager.zig");
const forward = @import("../l3/forward.zig");
const dhcp_leases = @import("../services/dhcp/leases.zig");
const dns_service = @import("../services/dns/service.zig");
const control_host = @import("../control/host.zig");
const control_offload = @import("../control/offload.zig");
const control_server = @import("../control/server.zig");
const control_state = @import("../control/state.zig");
const firewall_counters = @import("../control/firewall_counters.zig");
const netlink = @import("../port/linux/netlink.zig");

pub const Timestamp = if (@sizeOf(usize) >= 8) u64 else u32;

pub fn timestamp(ms: i64) Timestamp {
    const value: u64 = @intCast(@max(ms, 0));
    return if (@bitSizeOf(Timestamp) == 64) value else @truncate(value);
}

pub const Runtime = struct {
    running: std.atomic.Value(bool) = .init(false),
    port_count: std.atomic.Value(u32) = .init(0),
    started_ms: std.atomic.Value(Timestamp) = .init(0),
};

pub const ReadyFn = *const fn (ctx: ?*anyopaque) void;

pub const Options = struct {
    state_dir: ?[]const u8 = "/run/vrouter",
    allow_host_changes: bool = true,
    enable_monitor: bool = true,
    injected: []const manager_mod.InjectedPort = &.{},
    runtime: ?*Runtime = null,
    on_ready: ?ReadyFn = null,
    on_ready_ctx: ?*anyopaque = null,
};

pub fn run(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *const schema.Config,
    stop: *const std.atomic.Value(bool),
    options: Options,
) !void {
    var logger = log.Logger.init(io, cfg.log);

    // Reserve the control socket before any host mutation so a second daemon
    // fails fast instead of racing the first one's routes and journal.
    var control_path: ?[]u8 = null;
    defer if (control_path) |path| gpa.free(path);
    var control: ?control_server.Server = null;
    defer if (control) |*server| server.deinit();
    if (options.state_dir) |state_dir| {
        const path = try std.fs.path.join(gpa, &.{ state_dir, "control.sock" });
        control_path = path;
        control = try control_server.Server.init(io, gpa, path, .{});
    }

    var host: ?control_host.Host = null;
    defer if (host) |*h| h.deinit();
    var offload_checkpoint: usize = 0;
    if (control_offload.isEnabled(cfg)) {
        if (!options.allow_host_changes) return error.Unsupported;
        const state_dir = options.state_dir orelse return error.InvalidArgument;
        host = try control_host.Host.init(io, gpa, state_dir, cfg.instance);
        offload_checkpoint = try host.?.checkpoint();
    }
    errdefer if (host) |*h| {
        _ = h.downTo(offload_checkpoint) catch {};
    };

    var offload_plan = control_offload.Plan.init(gpa);
    defer offload_plan.deinit();
    if (host) |*h| {
        offload_plan = control_offload.apply(io, gpa, h, cfg) catch |err| {
            logger.err("kernel offload: {s}; run `vrouter down -c <config>` to repair", .{
                @errorName(err),
            });
            return err;
        };
        for (offload_plan.devices) |device| {
            logger.info("offload bridge={s} kernel={s} trunk={s}", .{
                device.bridge_name,
                device.kernel_bridge,
                device.veth_vrouter,
            });
        }
        for (offload_plan.skipped) |port_name| {
            const port = cfg.ports.get(port_name) orelse continue;
            if (port.storm_control != 0) {
                logger.warn(
                    "kernel offload: storm_control is not enforced on offloaded members; set it to 0 to silence this warning",
                    .{},
                );
                break;
            }
        }
    }

    const extras = try gpa.alloc(manager_mod.ExtraPort, offload_plan.synthetic.len);
    defer gpa.free(extras);
    for (offload_plan.synthetic, 0..) |synthetic, index| {
        extras[index] = .{
            .config_name = synthetic.config_name,
            .device = synthetic.device,
        };
    }

    var manager = try manager_mod.Manager.openFromConfigWithOptions(gpa, io, cfg, .{
        .skip = offload_plan.skipped,
        .extras = extras,
        .injected = options.injected,
    });
    defer manager.deinit(io);
    if (options.enable_monitor) try manager.enableMonitor();
    try manager.refreshAll(io);

    const port_entries = try gpa.alloc(forward.PortEntry, manager.count());
    defer gpa.free(port_entries);
    for (manager.entries, 0..) |entry, idx| {
        port_entries[idx] = .{
            .id = entry.port.info().id,
            .config_name = entry.config_name,
            .port = entry.port,
        };
    }

    var forwarder = try forward.Forwarder.fromConfig(gpa, io, cfg, port_entries);
    defer forwarder.deinit();

    const counter_packets = try gpa.alloc(u64, forwarder.firewallRuleCount());
    defer gpa.free(counter_packets);
    var counter_save_ms = nowMs(io);
    var counter_warned = false;

    var lease_store: ?dhcp_leases.Store = null;
    defer if (lease_store) |*store| store.deinit();
    if (cfg.lease_db) |db_path| {
        lease_store = dhcp_leases.Store.init(gpa, io, db_path) catch |err| {
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

    var upstreams: ?[]types.Ipv4 = null;
    defer if (upstreams) |items| gpa.free(items);
    var dns_zones: ?[]dns_service.Zone = null;
    defer if (dns_zones) |zones| {
        for (zones) |zone| gpa.free(zone.upstreams);
        gpa.free(zones);
    };
    var dns: ?dns_service.Service = null;
    defer if (dns) |*service| service.deinit();
    if (cfg.dns.upstreams.len != 0 or cfg.dns.zones.len != 0) {
        const items = try gpa.alloc(types.Ipv4, cfg.dns.upstreams.len);
        upstreams = items;
        for (cfg.dns.upstreams, 0..) |text, upstream_index| {
            items[upstream_index] = types.Ipv4.parse(text) catch return error.InvalidArgument;
        }
        if (cfg.dns.zones.len != 0) {
            const zones = try gpa.alloc(dns_service.Zone, cfg.dns.zones.len);
            dns_zones = zones;
            for (cfg.dns.zones, 0..) |zone_cfg, zone_index| {
                const zone_upstreams = try gpa.alloc(types.Ipv4, zone_cfg.upstreams.len);
                for (zone_cfg.upstreams, 0..) |text, upstream_index| {
                    zone_upstreams[upstream_index] = types.Ipv4.parse(text) catch return error.InvalidArgument;
                }
                zones[zone_index] = .{
                    .suffix = zone_cfg.suffix,
                    .upstreams = zone_upstreams,
                };
            }
        }
        const listen = types.Ipv4.parse(cfg.dns.listen orelse
            return error.InvalidArgument) catch return error.InvalidArgument;
        dns = dns_service.Service.init(io, gpa, .{
            .listen_ip = listen,
            .upstreams = items,
            .cache = cfg.dns.cache,
            .cache_max_entries = cfg.dns.max_entries,
            .tcp = cfg.dns.tcp,
            .zones = if (dns_zones) |zones| zones else &.{},
        }) catch |err| {
            logger.err(
                "dns listen={f}: {s}; assign the address first with `vrouter iface set <dev> <cidr>`",
                .{ listen, @errorName(err) },
            );
            return err;
        };
        try dns.?.start();
        logger.info("dns listening={f} upstreams={d} cache={}", .{
            listen,
            items.len,
            cfg.dns.cache,
        });
    }

    try forwarder.announce(io);

    const started_ms = nowMs(io);
    if (control) |*server| {
        var snapshot: control_state.Snapshot = .{};
        buildSnapshot(
            &snapshot,
            cfg,
            &forwarder,
            manager.count(),
            options.state_dir.?,
            control_path.?,
            started_ms,
            started_ms,
        );
        server.publish(&snapshot);
        try server.start();
        logger.info("control socket={s}", .{control_path.?});
    }

    logger.info("started instance={s} ports={d} local={d} routes={d}", .{
        cfg.instance,
        manager.count(),
        forwarder.local.items.len,
        forwarder.fib.count(),
    });

    if (options.runtime) |runtime| {
        runtime.port_count.store(@intCast(manager.count()), .release);
        runtime.started_ms.store(timestamp(started_ms), .release);
        runtime.running.store(true, .release);
    }
    if (options.on_ready) |ready| ready(options.on_ready_ctx);

    var buf: [2048]u8 = undefined;
    var netlink_tick: u8 = 0;
    var lease_save_ms = nowMs(io);
    var control_tick_ms = started_ms;
    while (!stop.load(.acquire)) {
        forwarder.tick(io);
        const now = nowMs(io);
        if (control) |*server| {
            if (now - control_tick_ms >= 1_000) {
                var snapshot: control_state.Snapshot = .{};
                buildSnapshot(
                    &snapshot,
                    cfg,
                    &forwarder,
                    manager.count(),
                    options.state_dir.?,
                    control_path.?,
                    started_ms,
                    now,
                );
                server.publish(&snapshot);
                control_tick_ms = now;
            }
        }
        if (options.state_dir) |state_dir| {
            if (now - counter_save_ms >= 5_000) {
                saveFirewallCounters(
                    io,
                    gpa,
                    state_dir,
                    cfg.instance,
                    &forwarder,
                    counter_packets,
                ) catch |err| {
                    if (!counter_warned) {
                        logger.warn("firewall counters {s}: {s}", .{ state_dir, @errorName(err) });
                        counter_warned = true;
                    }
                };
                counter_save_ms = now;
            }
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

    if (options.runtime) |runtime| runtime.running.store(false, .release);

    if (lease_store) |*store| {
        store.save(forwarder.dhcpServers()) catch |err| {
            logger.warn("lease db save: {s}", .{@errorName(err)});
        };
    }

    if (options.state_dir) |state_dir| {
        saveFirewallCounters(
            io,
            gpa,
            state_dir,
            cfg.instance,
            &forwarder,
            counter_packets,
        ) catch |err| {
            if (!counter_warned) logger.warn("firewall counters {s}: {s}", .{ state_dir, @errorName(err) });
        };
    }

    if (dns) |service| {
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
            cfg.instance,
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

fn buildSnapshot(
    out: *control_state.Snapshot,
    cfg: *const schema.Config,
    forwarder: *const forward.Forwarder,
    port_count: usize,
    state_dir: []const u8,
    control_path: []const u8,
    started_ms: i64,
    updated_ms: i64,
) void {
    out.* = .{
        .instance = cfg.instance,
        .state_dir = state_dir,
        .control_path = control_path,
        .started_ms = started_ms,
        .updated_ms = updated_ms,
        .ports = @intCast(port_count),
        .counters = .{
            .forwarded = forwarder.counters.forwarded,
            .bridged = forwarder.counters.bridged,
            .dropped = forwarder.counters.dropped,
            .firewall_dropped = forwarder.counters.firewall_dropped,
            .pending_queued = forwarder.counters.pending_queued,
            .pending_flushed = forwarder.counters.pending_flushed,
            .conntrack_created = forwarder.conntrack.counters.created,
            .conntrack_removed = forwarder.conntrack.counters.removed,
            .conntrack_hits = forwarder.conntrack.counters.hits,
            .conntrack_misses = forwarder.conntrack.counters.misses,
            .conntrack_table_full = forwarder.conntrack.counters.table_full,
            .snat_packets = forwarder.counters.snat_packets,
            .dnat_packets = forwarder.counters.dnat_packets,
            .icmp_translated = forwarder.counters.icmp_translated,
            .dhcp_offers = forwarder.counters.dhcp_offers,
            .dhcp_acks = forwarder.counters.dhcp_acks,
            .dhcp_requests = forwarder.counters.dhcp_requests,
            .dhcp_client_bound = forwarder.counters.dhcp_client_bound,
            .storm_dropped = forwarder.counters.storm_dropped,
            .stp_bpdus_rx = forwarder.counters.stp_bpdus_rx,
            .stp_bpdus_tx = forwarder.counters.stp_bpdus_tx,
            .stp_filtered = forwarder.counters.stp_filtered,
            .stp_invalid = forwarder.counters.stp_invalid,
        },
    };

    for (forwarder.snat_rules.items) |rule| {
        if (out.snat_len >= control_state.max_snat) break;
        out.snat[out.snat_len] = .{
            .out = portName(forwarder.ports, rule.port),
            .addr = rule.addr,
        };
        out.snat_len += 1;
    }

    for (forwarder.forward_rules.items) |rule| {
        if (out.port_forward_len >= control_state.max_port_forward) break;
        out.port_forward[out.port_forward_len] = .{
            .proto = rule.proto,
            .ext_port = rule.ext_port,
            .to_addr = rule.to_addr,
            .to_port = rule.to_port,
            .ingress = if (rule.ingress) |id| portName(forwarder.ports, id) else "",
        };
        out.port_forward_len += 1;
    }

    out.conntrack_total = forwarder.conntrack.count;
    for (forwarder.conntrack.entries.items) |entry_opt| {
        if (out.conntrack_len >= control_state.max_conntrack) break;
        const entry = entry_opt orelse continue;
        var sampled: control_state.Conntrack = .{
            .proto = entry.original.proto,
            .state = @tagName(entry.state),
            .src = entry.original.src,
            .sport = entry.original.sport,
            .dst = entry.original.dst,
            .dport = entry.original.dport,
            .packets = entry.packets,
            .bytes = entry.bytes,
            .reply_packets = entry.reply_packets,
            .reply_bytes = entry.reply_bytes,
            .created_ms = entry.created_ms,
            .last_seen_ms = entry.last_seen_ms,
            .timeout_ms = entry.timeout_ms,
        };
        if (entry.translated) |translated| {
            sampled.translated_src = translated.src;
            sampled.translated_sport = translated.sport;
            sampled.translated_dst = translated.dst;
            sampled.translated_dport = translated.dport;
        }
        out.conntrack[out.conntrack_len] = sampled;
        out.conntrack_len += 1;
    }
}

fn portName(ports: []const forward.PortEntry, id: types.PortId) []const u8 {
    for (ports) |entry| {
        if (entry.id.eql(id)) return entry.config_name;
    }
    return "";
}

fn saveFirewallCounters(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    instance: []const u8,
    forwarder: *const forward.Forwarder,
    packets: []u64,
) !void {
    const count = forwarder.snapshotFirewallPackets(packets);
    try firewall_counters.save(io, gpa, state_dir, instance, packets[0..count], .{
        .firewall_dropped = forwarder.counters.firewall_dropped,
        .firewall_spoofed = forwarder.counters.firewall_spoofed,
        .icmp_rate_limited = forwarder.counters.icmp_rate_limited,
        .arp_rate_limited = forwarder.counters.arp_rate_limited,
        .dhcp_rate_limited = forwarder.counters.dhcp_rate_limited,
    });
}

fn logEvent(logger: *const log.Logger, event: *const netlink.Event) void {
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
