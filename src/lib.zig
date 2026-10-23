//! vNAT core library root.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

pub const version = build_options.version;

pub const types = @import("types.zig");
pub const errors = @import("errors.zig");
pub const io = @import("io.zig");
pub const log = @import("log.zig");

pub const config_schema = @import("config/schema.zig");
pub const config_parse = @import("config/parse.zig");
pub const config_validate = @import("config/validate.zig");

pub const port = @import("port/port.zig");
pub const memory_port = @import("port/memory.zig");
pub const buffer_pool = @import("port/pool.zig");

pub const journal = @import("control/journal.zig");
pub const firewall_counters = @import("control/firewall_counters.zig");
pub const control_host = if (builtin.os.tag == .linux)
    @import("control/host.zig")
else
    struct {};

pub const ethernet = @import("l2/ethernet.zig");
pub const stp = @import("l2/stp.zig");
pub const ipv4 = @import("l3/ipv4.zig");
pub const arp = @import("l3/arp.zig");
pub const fib = @import("l3/fib.zig");
pub const rate = @import("l3/rate.zig");
pub const conntrack = @import("nat/conntrack.zig");
pub const nat = @import("nat/nat.zig");
pub const icmp = @import("l3/icmp.zig");
pub const forward = @import("l3/forward.zig");
pub const dhcp_message = @import("services/dhcp/message.zig");
pub const dhcp_server = @import("services/dhcp/server.zig");
pub const dhcp_leases = @import("services/dhcp/leases.zig");
pub const dns_message = @import("services/dns/message.zig");
pub const dns_cache = @import("services/dns/cache.zig");
pub const dns_service = @import("services/dns/service.zig");

pub const linux_ports = if (builtin.os.tag == .linux)
    @import("port/linux/root.zig")
else
    struct {};

pub const manager = if (builtin.os.tag == .linux)
    @import("port/manager.zig")
else
    struct {};

pub const Config = config_schema.Config;
pub const Port = port.Port;
pub const PortId = types.PortId;
pub const MemoryPort = memory_port.MemoryPort;

test {
    _ = @import("types.zig");
    _ = @import("errors.zig");
    _ = @import("io.zig");
    _ = @import("log.zig");
    _ = @import("config/schema.zig");
    _ = @import("config/parse.zig");
    _ = @import("config/validate.zig");
    _ = @import("port/port.zig");
    _ = @import("port/memory.zig");
    _ = @import("port/pool.zig");
    _ = @import("control/journal.zig");
    _ = @import("control/firewall_counters.zig");
    if (builtin.os.tag == .linux) _ = @import("control/host.zig");
    _ = @import("l2/ethernet.zig");
    _ = @import("l2/stp.zig");
    _ = @import("l3/ipv4.zig");
    _ = @import("l3/arp.zig");
    _ = @import("l3/fib.zig");
    _ = @import("l3/rate.zig");
    _ = @import("nat/conntrack.zig");
    _ = @import("nat/nat.zig");
    _ = @import("l3/icmp.zig");
    _ = @import("l3/forward.zig");
    _ = @import("services/dhcp/message.zig");
    _ = @import("services/dhcp/server.zig");
    _ = @import("services/dhcp/leases.zig");
    _ = @import("services/dns/message.zig");
    _ = @import("services/dns/cache.zig");
    _ = @import("services/dns/service.zig");
    if (builtin.os.tag == .linux) {
        _ = @import("port/linux/root.zig");
        _ = @import("port/manager.zig");
    }
}
