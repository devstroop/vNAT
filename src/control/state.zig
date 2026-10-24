//! Read-only datapath snapshot published to the control socket. The service
//! loop owns the live tables; the control thread only sees this copy.

const std = @import("std");
const types = @import("../types.zig");

pub const max_snat = 64;
pub const max_port_forward = 128;
pub const max_conntrack = 256;

pub const Counters = struct {
    forwarded: u64 = 0,
    bridged: u64 = 0,
    dropped: u64 = 0,
    firewall_dropped: u64 = 0,
    pending_queued: u64 = 0,
    pending_flushed: u64 = 0,
    conntrack_created: u64 = 0,
    conntrack_removed: u64 = 0,
    conntrack_hits: u64 = 0,
    conntrack_misses: u64 = 0,
    conntrack_table_full: u64 = 0,
    snat_packets: u64 = 0,
    dnat_packets: u64 = 0,
    icmp_translated: u64 = 0,
    dhcp_offers: u64 = 0,
    dhcp_acks: u64 = 0,
    dhcp_requests: u64 = 0,
    dhcp_client_bound: u64 = 0,
    storm_dropped: u64 = 0,
    stp_bpdus_rx: u64 = 0,
    stp_bpdus_tx: u64 = 0,
    stp_filtered: u64 = 0,
    stp_invalid: u64 = 0,
};

pub const Snat = struct {
    out: []const u8 = "",
    addr: types.Ipv4 = .{},
};

pub const PortForward = struct {
    proto: u8 = 0,
    ext_port: u16 = 0,
    to_addr: types.Ipv4 = .{},
    to_port: u16 = 0,
    ingress: []const u8 = "",
};

pub const Conntrack = struct {
    proto: u8 = 0,
    state: []const u8 = "",
    src: types.Ipv4 = .{},
    sport: u16 = 0,
    dst: types.Ipv4 = .{},
    dport: u16 = 0,
    translated_src: ?types.Ipv4 = null,
    translated_sport: u16 = 0,
    translated_dst: ?types.Ipv4 = null,
    translated_dport: u16 = 0,
    packets: u64 = 0,
    bytes: u64 = 0,
    reply_packets: u64 = 0,
    reply_bytes: u64 = 0,
    created_ms: i64 = 0,
    last_seen_ms: i64 = 0,
    timeout_ms: i64 = 0,
};

pub const Snapshot = struct {
    instance: []const u8 = "",
    state_dir: []const u8 = "",
    control_path: []const u8 = "",
    started_ms: i64 = 0,
    updated_ms: i64 = 0,
    ports: u32 = 0,
    counters: Counters = .{},
    snat: [max_snat]Snat = @splat(.{}),
    snat_len: usize = 0,
    port_forward: [max_port_forward]PortForward = @splat(.{}),
    port_forward_len: usize = 0,
    conntrack: [max_conntrack]Conntrack = @splat(.{}),
    conntrack_len: usize = 0,
    conntrack_total: u32 = 0,

    pub fn snatSlice(self: *const Snapshot) []const Snat {
        return self.snat[0..self.snat_len];
    }

    pub fn portForwardSlice(self: *const Snapshot) []const PortForward {
        return self.port_forward[0..self.port_forward_len];
    }

    pub fn conntrackSlice(self: *const Snapshot) []const Conntrack {
        return self.conntrack[0..self.conntrack_len];
    }
};

pub fn protoName(proto: u8) []const u8 {
    return switch (proto) {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        else => "other",
    };
}
