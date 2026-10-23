# vNAT — Core Scope (v1)

> This is the functional contract for the first release. If it is not in this
> document, it is not in v1.
> Platform detail: [ANDROID.md](./ANDROID.md). Design: [ARCHITECTURE.md](./ARCHITECTURE.md).

## 1. What "router" means here

vNAT is a **userspace L2/L3 forwarding engine**. It opens interfaces directly,
moves frames/packets between them, and implements bridging, routing, NAT,
DHCP, DNS and a packet filter. A kernel fast path may be used as an
optimization, but the portable userspace path is the reference behavior.

It is *not* a wrapper around `iptables`/`nft`/`ip`. It may **program** those
subsystems for offload, but it must still work when they are unavailable.

```
        ┌──────────────────────── control plane ───────────────────────┐
        │ config · CLI · local API · journal · status · events         │
        └──────────────────────────────┬───────────────────────────────┘
                                       │ desired state
        ┌──────────────────────────────▼───────────────────────────────┐
        │                         vNAT core                            │
        │                                                              │
        │  ┌─────────┐   ┌──────────┐   ┌────────┐   ┌─────────────┐   │
        │  │ L2 port │──▶│  bridge  │──▶│ router │──▶│ NAT/conntrack│  │
        │  │ L3 port │   │  (FDB,   │   │ (FIB,  │   │  firewall    │  │
        │  │         │◀──│  VLAN,   │◀──│  ARP,  │◀──│  DHCP  DNS   │  │
        │  └─────────┘   │  STP)    │   │  ICMP) │   └─────────────┘   │
        │                └──────────┘   └────────┘                     │
        └──────────────────────────────────────────────────────────────┘
```

## 2. Interface model

### 2.1 Port types

| Type | Direction | Unit | Examples |
|---|---|---|---|
| `L2Port` | ingress/egress | Ethernet frame (optional 802.1Q) | `eth0`, `wlan0`, `usb0`, `ap0`, `rmnet*`, TAP, bridge member |
| `L3Port` | ingress/egress | IPv4/IPv6 packet | TUN, Android `VpnService` fd, tunnel |
| `NullPort` | — | drops + counts | `/dev/null`, testing |

A router instance owns a set of ports. A bridge owns a subset of L2 ports. A
port belongs to at most one bridge or one router zone at a time.

### 2.2 Port properties

Every port exposes:

- stable `PortId` (generated, persisted per `name`+`ifindex`+`mac`)
- `name`, `ifindex`, `kind`, `mac`, `mtu`, `link_state`, `speed` (if known)
- `capabilities`: `promiscuous`, `multicast`, `broadcast`, `vlan_filter`,
  `checksum_offload`, `gso`, `tx_ring`, `admin_up`
- `stats`: rx/tx packets, bytes, drops by reason, errors

### 2.3 Opening a port (Linux)

| Kind | Mechanism | Privilege |
|---|---|---|
| L2 | `AF_PACKET` `SOCK_RAW`, bind to ifindex, `PACKET_MMAP`/TPACKET_V3 optional | `CAP_NET_RAW` |
| L3 | `/dev/net/tun` + `TUNSETIFF` (`IFF_TUN \| IFF_NO_PI`), configure addr/MTU | `CAP_NET_ADMIN` |
| L2 virtual | `/dev/net/tun` + `IFF_TAP` | `CAP_NET_ADMIN` |
| monitor | rtnetlink `RTMGRP_LINK`, `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV6_IFADDR`, `RTMGRP_NEIGH` | — |

- Config creation: set `"create": "tun"` (L3) or `"create": "tap"` (L2) to
  have vNAT create the device; without `create`, the device must already exist.
- Default: **no kernel bridge**, vNAT bridges in userspace. Optional
  `bridge.offload = "kernel"` creates a kernel bridge and enslaves ports for
  higher throughput.
- Checksums: do not request hardware offload on TUN; compute in software so the
  same code is correct on Android. (`TUNSETOFFLOAD` is an opt-in optimization
  with an explicit fallback.)

### 2.4 Opening a port (Android)

| Mode | Port | Mechanism |
|---|---|---|
| VPN (no root) | L3 | `VpnService.Builder.establish()` fd passed over JNI |
| VPN (no root) | L3 uplink | protected `Socket`/`DatagramSocket` (bypasses VPN) |
| Root | L2 | `AF_PACKET` on `wlan0`/`ap0`/`usb0`/`rmnet*` |
| Root | L3 | TUN created by vNAT or injected by host |

Host integration is defined in [ANDROID.md](./ANDROID.md).

### 2.5 Hotplug and lifecycle

- Link up/down, address add/remove, MTU change, carrier loss, interface
  disappearance are events.
- On disappearance: flush neighbors, routes, conntrack entries and DHCP leases
  bound to that port; emit `port_removed`; do not crash.
- `admin_up` is a vNAT concept (port enabled) separate from kernel link state.

### 2.6 Frame/packet representation

```zig
pub const Frame = struct {
    port: PortId,
    data: []u8,        // points into a pooled buffer
    len: u32,
    vlan: ?VlanTag,    // stripped/parsed tag, if any
    hw_offload: Offload, // checksum/gso metadata for the kernel fast path
};
```

- Buffers come from a per-core pool; no allocation on the fast path.
- Bounds-checked parsing; malformed frames are counted, never panic.
- Ethernet padding/trailer handling; VLAN tag preservation on egress.

## 3. L2 bridge

### 3.1 Behavior

- MAC learning: `(bridge, vlan, src_mac) → port`; default aging 300 s.
- Forwarding:
  - known unicast → learned port
  - unknown unicast / broadcast / multicast → flood to all member ports
    (except ingress)
  - no hairpin unless configured
- STP: 802.1D basic (blocking/listening/learning/forwarding) **optional**;
  default off for small trusted topologies, on when `bridge.stp = true`.
- Loop protection: per-port ingress rate limit + storm control.
- Port isolation and per-port VLAN membership.

### 3.2 VLAN

- 802.1Q parse/insert; TPID 0x8100 (0x88A8 optional later).
- Per-port `pvid` (untagged ingress VLAN) and `tagged` set.
- Trunk ports carry multiple VLANs; access ports carry one.
- VLAN-aware bridging: FDB keyed by `(vlan, mac)`.
- No QinQ in v1.

### 3.3 Offload

`bridge.offload = "none" | "kernel"`:
- `none`: userspace forwarding (default, portable).
- `kernel` (Linux): create `br-<name>`, enslave ports, set `vlan_filtering`.
  vNAT still owns configuration and monitoring. Requires `CAP_NET_ADMIN`.

### 3.4 Counters

Per bridge/port: rx/tx frames, bytes, flooded, learned, aged, drops
(unknown-vlan, isolation, storm).

## 4. L3 router

### 4.1 Forwarding

- IPv4 and IPv6 forwarding between L3 ports and bridge interfaces (SVIs).
- Longest-prefix-match FIB (compressed trie, v4/v6).
- Route sources: connected, static, DHCP/client, kernel (import mode).
- Policy: source-based rules (`from`, `iif`, `mark`) evaluated before the FIB.
- TTL / hop-limit decrement; drop if 0/1 and send ICMP Time Exceeded.
- ICMP: destination unreachable, fragmentation needed (with PMTU), echo
  reply, parameter problem.
- No router-on-a-stick special case needed; SVIs are just interfaces.

### 4.2 Neighbor discovery

- ARP (IPv4): cache with reachable/stale/probe states, `arp_accept`,
  proxy ARP, gratuitous ARP on address/port change.
- NDP (IPv6): neighbor cache, router/neighbor advertisements (v1.1).
- Static neighbors for constrained links.
- Neighbor table exposed via status and flushed on port loss.

### 4.3 Fragmentation and MTU

- Forward fragments without reassembly by default.
- MSS clamping on TCP SYN/SYN-ACK when `mtu.clamp = true` (recommended).
- Generate ICMP Fragmentation Needed with the correct next-hop MTU.
- Never emit a frame larger than the egress MTU; drop + count otherwise.
- DF honored; no PMTUD blackhole workaround in v1 beyond MSS clamp.

### 4.4 Multicast / broadcast

- IPv4 broadcast → L2 broadcast on the egress bridge.
- IPv6 multicast → mapped multicast MAC.
- IGMP/MLD snooping: out of scope v1; flood multicast.

### 4.5 Interfaces (logical)

- `bridge.<name>` (SVI) for routed VLANs — v1.0.
- `vlan.<parent>.<id>` for routed VLANs without a bridge — v1.1.
- Loopback/link-local handling (127.0.0.0/8, ::1, fe80::/10).

### 4.6 R2 implementation notes (current)

- Static interface addresses create connected routes; static routes use `via`
  and `dev`.
- ARP requests are answered only for an exact local address on the ingress
  port; replies are learned. Active probing, gratuitous ARP and proxy ARP are
  not enabled yet.
- Non-first fragments are forwarded without L4 inspection; there is no
  reassembly or fragmentation. Packets above the egress MTU produce ICMP
  Fragmentation Needed.
- Tagged frames are dropped until VLAN support (R5).
- TCP/UDP checksums are recomputed on forwarded, non-fragmented packets
  (ADR-007).
- Gratuitous ARP is sent for configured local addresses when `vnatd` starts.
  On a neighbor miss, up to 32 packets are queued for 1 s and flushed when the
  ARP reply arrives; overflow/expiry drops are counted. Proxy ARP and periodic
  neighbor refresh are not enabled yet.
- TUN/L3 ports carry bare IPv4 in both directions. Local echo and ICMP errors
  are written back as bare IP; TUN ingress can be routed to L2 or TUN egress.
- `vnat iface`/`vnat route` mutations are journaled under `$VNAT_RUN_DIR` and
  restored by `vnat down` (§9.4).

## 5. NAT and conntrack

### 5.1 Conntrack

The NAT engine requires connection tracking; the firewall reuses it.

```zig
pub const FlowKey = struct { proto: u8, src: IpAddr, sport: u16, dst: IpAddr, dport: u16 };
pub const FlowState = enum { new, established, related, closing };
```

- Table keyed by 5-tuple; reply direction keyed by the translated tuple.
- Timeouts (defaults, configurable):
  - TCP established 300 s, TCP SYN 10 s, TCP FIN/RST 10 s
  - UDP 30 s (streaming 120 s optional)
  - ICMP 30 s
  - Generic 60 s
- GC: 1 s sweep, incremental; hard cap `max_entries` (default 65,536).
- Fragments: first-fragment creates state; subsequent fragments matched by
  `(src, dst, id, proto)`; no reassembly in v1.
- Exposed in `vnat conntrack` with bytes/packets/age/state.

### 5.2 SNAT / masquerade

- Per egress interface, translate source to the egress address (or a pool).
- Port allocation: preserve original when free, otherwise deterministic
  randomized allocation from the ephemeral range.
- Endpoint-independent mapping by default (friendly to peer-to-peer); an
  `endpoint_dependent` option exists for strict deployments.
- ICMP query ID translation.
- Hairpin: traffic from a LAN client to the public address/port is translated
  back to the internal target.

### 5.3 DNAT / port forwarding

```
vnat nat add port-forward --proto tcp --ext-port 8080 --to 10.10.0.5:80
vnat nat add port-forward --proto udp --ext-port 51820 --to 10.10.0.7:51820
```

- Match on egress port + protocol + external port (+ optional source CIDR).
- Rewrite destination and reverse state; optional source rewriting for
  hairpin.
- Range mapping `8080-8090:80-90` — v1.1.

### 5.4 R3 implementation notes (current)

- Conntrack uses a single table with both directions mapped to one entry and
  a zone (ingress/egress port id) in the key; 64-way sharding is deferred. GC
  is a 1 s full sweep, cap 65,536 entries.
- TCP uses flag-based new/established/closing states with SYN 10 s,
  established 300 s and FIN 120 s/RST 10 s timeouts. UDP and ICMP echo use
  30 s; other protocols are not tracked yet.
- SNAT/masquerade applies to TCP, UDP and ICMP echo. The original source port
  is preserved when free; collisions use a deterministic hash/probe from
  1024–65535. Mapping is per flow (endpoint-independent mapping is deferred).
- ICMP echo identifiers are translated; ICMP errors are not translated yet.
- Masquerade `out` must resolve to a static interface address. DHCP uplinks
  fail with `InvalidArgument` until R4.
- Fragments and non-echo ICMP on an egress with masquerade are dropped and
  counted (`nat_unsupported`) rather than leaking private sources.
- Checksums are recomputed in full after NAT; incremental updates are pending.
- DNAT/port forwarding and hairpin are not implemented yet.

### 5.5 Out of scope

NAT64/464XLAT, ALGs (FTP/SIP/PPTP), SIP/SDP rewriting, deterministic port
preservation across restarts.

## 6. Packet filter

### 6.1 Rules

Ordered, first-match. Match fields: `iif`, `oif`, `src`, `dst`, `proto`,
`sport`, `dport`, `ct_state`, `mark`, `dscp`. Actions: `accept`, `drop`,
`reject`, `log`, `mark`, `snat`, `dnat`.

- Default policy: `inbound: drop`, `forward: drop`, `outbound: accept`
  (configurable; this is a router, not a transparent bridge).
- Conntrack integration: `ct_state established,related` accept shortcut.
- Stateful by default for TCP/UDP; stateless option per rule.

### 6.2 Limits

- Rule count cap (default 10,000) with compile-time validation.
- No L7/app identification, no IPS, no geo-IP.

## 7. DHCPv4 server

- Per downstream interface / subnet.
- Pool, static reservations by MAC or client-id, lease time, renewal/rebind.
- Options: router, DNS, domain, MTU, NTP, lease time, vendor class.
- Conflict detection: ARP probe before offer; handle DECLINE.
- Persisted leases (`/var/lib/vnat/leases.json`), restored on start.
- DHCP relay: out of scope v1.
- DHCPv6/RA: v1.1.

## 8. DNS

- Forwarder over UDP (TCP fallback), per-network upstreams.
- Cache respecting TTL, negative caching, max entries.
- Local zone: `vnat.` / `router.vnat.` for status (opt-in).
- Split DNS by domain suffix.
- DoH/DoT: later.
- Serves DHCP-advertised DNS; binds to router addresses only.

## 9. Control plane

### 9.1 Config

Declarative JSON (versioned, with JSON Schema). Example (the canonical,
machine-checked configs live in `examples/`):

```json
{
  "version": 1,
  "instance": "travel-router",
  "log": { "level": "info", "format": "json" },
  "ports": {
    "uplink":  { "kind": "l2", "device": "wlan0" },
    "lan":     { "kind": "l2", "device": "usb0" },
    "vpn0":    { "kind": "l3", "device": "vnat0", "create": "tun", "mtu": 1380 }
  },
  "bridges": {
    "lan-br": { "ports": ["lan"], "stp": false, "vlan_aware": true }
  },
  "interfaces": {
    "lan0": { "bridge": "lan-br", "address": "10.10.0.1/24" },
    "wan0": { "port": "uplink", "address": "dhcp" }
  },
  "routes": [
    { "dst": "0.0.0.0/0", "via": "192.168.1.1", "dev": "wan0" }
  ],
  "nat": {
    "masquerade": [{ "out": "wan0" }],
    "port_forward": [
      { "proto": "tcp", "ext_port": 8080, "to": "10.10.0.5:80" }
    ]
  },
  "dhcp": [
    { "iface": "lan0", "pool": "10.10.0.100-10.10.0.200", "lease": "12h" }
  ],
  "dns": { "upstreams": ["1.1.1.1", "9.9.9.9"], "cache": true },
  "firewall": { "default_in": "drop", "default_forward": "drop" }
}
```

Rules for config:
- Unknown keys are errors (catches typos).
- Version 1 grows by adding *optional* keys in the milestone that implements
  them (R4 DHCP/DNS, R5 VLAN/STP, R6 firewall); existing keys never change
  meaning.
- Validation before any mutation; all-or-nothing apply.
- `vnat up` computes a diff and journals each mutation (R7; R2 exposes direct
  `vnat iface`/`vnat route` verbs).
- Live-reload only for fields marked hot; otherwise restart required.

### 9.2 CLI

Implemented in R2:

```
vnat validate <config.json>
vnat port list
vnat status [-c] <config.json>
vnat iface set|del <dev> <cidr> [-c <config>]
vnat iface up|down <dev> [-c <config>]
vnat route add|del <dst> [via <ip>] dev <dev> [metric <n>] [table <n>] [-c <config>]
vnat down [-c <config>]
vnat journal [-c <config>]
vnat selftest ...
```

Planned with their milestones:

```
vnat up -c /etc/vnat/vnat.json          # R7 control plane
vnat bridge create lan                   # R5
vnat nat add masquerade --out wan0       # R3
vnat dhcp status                         # R4
vnat dns query example.com               # R4
vnat conntrack list [--state established] # R3
vnat firewall list                       # R6
vnat pcap --iface lan --write cap.pcap   # R9
vnat doctor                              # R7
```

Every command supports `--json`. Exit codes are stable.

### 9.3 Local API

- Unix domain socket (`/run/vnat/control.sock`), mode `0660`, group `vnat`.
- Line-delimited JSON requests/responses (easy to script) or JSON-RPC 2.0.
- No TCP listener by default. If enabled, requires a token and TLS.
- Streaming events: `port_up`, `port_down`, `link_change`, `dhcp_lease`,
  `nat_expired`, `error`.

### 9.4 Journal and rollback

R2 records one **forward operation** per JSON line under
`$VNAT_RUN_DIR/<instance>.journal` (default `/run/vnat`). The inverse is derived
by `vnat down`; the journal is fsynced and atomically replaced before the
netlink call:

```json
{"op":"addr_add","dev":"lan0","cidr":"10.10.0.1/24"}
{"op":"route_add","dst":"0.0.0.0/0","via":"192.168.1.1","dev":"wan0","metric":0,"table":0}
{"op":"link","dev":"lan0","up":true}
```

- `vnat iface del` and `vnat route del` only remove state recorded as
  vNAT-owned; unmanaged state must be removed with `ip`.
- `vnat down` applies the inverse of each record in reverse order, treating
  "already absent" and "already present" as success. A fully successful
  rollback deletes the journal; failures keep it for inspection and retry.
- If a mutation fails after its journal write, the record is removed.
- A crash between the write and the mutation leaves an idempotent record; the
  next `vnat down` cleans it up.
- `/run` is used because host state is recreated per boot; persisting a journal
  across a reboot would reference state that no longer exists.
- Pending/applied status, sequence numbers, batch apply, PID locking and
  crash reconciliation land with the R7 control plane (ADR-006).
- The journal never contains secrets.

### 9.5 C ABI (Android / future desktop)

```c
typedef void* vnat_t;
vnat_t vnat_create(const char* config_json);
int    vnat_start(vnat_t);
int    vnat_stop(vnat_t);
void   vnat_destroy(vnat_t);
int    vnat_set_port_fd(vnat_t, const char* name, int fd); // VpnService
int    vnat_set_event_cb(vnat_t, cb, void*);
int    vnat_get_status(vnat_t, vnat_status_t*);
const char* vnat_version(void);
```

Rules: opaque handles, fixed-size structs, no allocations across the boundary,
stable error codes, callbacks on one thread.

## 10. Platform matrix (v1)

| Feature | Linux | Android VPN (no root) | Android root |
|---|---|---|---|
| L2 ports (AF_PACKET) | ✅ | ❌ | ✅ |
| L3 ports (TUN/fd) | ✅ | ✅ (one VpnService fd) | ✅ |
| Userspace bridge | ✅ | ❌ | ✅ |
| Kernel bridge offload | ✅ | ❌ | ⚠️ (kernel support varies) |
| IPv4 routing | ✅ | ✅ (on-device) | ✅ |
| NAT (SNAT/DNAT) | ✅ | ✅ (app traffic) | ✅ |
| DHCP server | ✅ | ❌* | ✅ |
| DNS forwarder | ✅ | ✅ | ✅ |
| Firewall | ✅ | ✅ | ✅ |
| Port forwarding | ✅ | ❌* | ✅ |
| Hotplug | netlink | host callbacks | netlink + host |
| Journal/rollback | ✅ | n/a | ✅ (critical) |

\* Android VPN mode cannot serve tethered clients; see [ANDROID.md](./ANDROID.md).

## 11. Data-plane invariants

1. Never forward a frame back out of its ingress port (bridge flood excepted).
2. Never forward between ports that are not in the same bridge/router instance.
3. Every egress packet has a correct checksum (software path).
4. Never emit a packet larger than the egress MTU.
5. Drop + count, never panic, on malformed input.
6. No allocation on the fast path; buffer pools only.
7. Flush per-port state (neighbors, routes, conntrack, leases) when a port
   disappears.
8. Default inbound/forward policy is drop.
9. Journal before mutation; no silent host changes.
10. `vnat down` is idempotent and restores the pre-start state.

## 12. Performance budgets (v1)

| Path | Target |
|---|---|
| Linux veth→veth L3 forward, 1500 B | ≥ 1 Gbps, ≥ 1 Mpps in 64 B |
| Linux AF_PACKET L2 bridge | ≥ 2 Gbps |
| NAT (conntrack) | ≥ 800 Mbps |
| Android VPN mode | ≥ 150 Mbps |
| Android root mode | ≥ 300 Mbps |
| Added latency | < 1 ms p99 on LAN |

Techniques: `recvmmsg`/`sendmmsg`, `PACKET_MMAP`, multi-queue, per-core
workers, buffer pools, batch processing, optional AF_XDP (post-v1).

## 13. Explicitly out of scope for v1

- GUI / web UI / TUI beyond `status --watch`.
- Overlay/P2P/VPN protocols (future uplink port).
- Dynamic routing protocols.
- IPv6 RA/DHCPv6 (v1.1), NAT64.
- ALGs, captive portal, 802.1X, QoS shaping.
- macOS/Windows.
- Clustering/HA.
