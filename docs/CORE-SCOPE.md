# vNAT — Core Scope (v1)

> This is the functional contract for the first release. If it is not in this
> document, it is not in v1.
> Platform detail: [ANDROID.md](./ANDROID.md). Design: [ARCHITECTURE.md](./ARCHITECTURE.md).

## 0. Status vocabulary

- **implemented**: code exists in `src/`.
- **tested**: covered by unit or netns tests.
- **CI-verified**: the test runs in `.github/workflows/ci.yml`.
- **planned**: specified but not implemented.
- **deferred**: explicitly postponed to a later milestone.

A capability is only promoted to **tested** or **CI-verified** when the
corresponding evidence exists.

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
  have vNAT create the device. Existing L2 devices are opened via `AF_PACKET`;
  existing L3 devices are rejected because vNAT cannot adopt their fd from
  config (hosts may still inject a TUN fd through the C ABI).
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
- Implemented: userspace MAC learning/FDB aging, known-unicast, unknown-
  unicast and broadcast flooding, per-bridge SVI addressing and DHCP service
  on any member port. Router-routed traffic resolves neighbours across the
  bridge and preserves the bridge zone in conntrack.
- STP: 802.1D basic (blocking/listening/learning/forwarding) **optional**;
  default off for small trusted topologies. `bridge.stp = true` runs
  userspace root election, BPDU exchange every 2s, and 15s forward-delay
  transitions. RSTP and per-port STP tuning are future work.
- Loop protection: per-port ingress flooded-frame rate limit (storm control).
  `ports.<name>.storm_control` caps broadcast/multicast/unknown-unicast
  frames per second (default 1000, `0` disables); excess is dropped and
  counted as `storm`. Mirroring/MAC-flap loop detection remains future work.
- Port isolation and per-port VLAN membership.

### 3.2 VLAN

- 802.1Q parse/insert; TPID 0x8100 (0x88A8 optional later).
- Per-port `pvid` (untagged ingress VLAN), `tagged` set and
  `storm_control`.
- Trunk ports carry multiple VLANs; access ports carry one.
- VLAN-aware bridging: FDB keyed by `(vlan, mac)`. `vlan_aware = true`
  enables filtering; non-VLAN bridges reject `pvid`/`tagged` and drop tagged
  frames. Interface SVIs default to VLAN 1 on a VLAN-aware bridge.
- Receive-side offload may strip the 802.1Q header; the AF_PACKET port
  reconstructs it from `PACKET_AUXDATA` before ingress classification.
- No QinQ in v1.

### 3.3 Offload

`bridge.offload = "none" | "kernel"`:
- `none`: userspace forwarding (default, portable).
- `kernel` (Linux): create one kernel bridge and enslave the configured
  members. vNAT opens the peer of a veth trunk as a synthetic L2 port, so SVIs,
  routing, NAT, DHCP, DNS and firewall remain in userspace. When
  `vlan_aware = true`, the kernel bridge filters VLANs and the trunk carries
  PVID 1 untagged plus the union of member/SVI VLANs tagged. `bridge.stp`
  enables kernel STP and disables the userspace instance.
- Kernel offload requires existing L2 members (`create` and `mtu` overrides
  are rejected), rejects a `pvid` that is also tagged, and never adopts an
  existing bridge or an already-enslaved port. Setup is journaled as one
  transaction; on failure the inverse is replayed to its checkpoint.
  `vnat down` removes the bridge, veth and VLAN entries and restores member
  link state.
- Per-port `storm_control` is not enforced on offloaded physical members; the
  bridge is forwarded by the kernel. vnatd warns while any offloaded member
  requests it (set `storm_control = 0` to silence).
- Firewall `iif`/`oif` references to offloaded physical members are rejected;
  use the bridge name to match the synthetic trunk.

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
- Validated MTUs are capped at 1600 bytes by the current 2048-byte userspace
  frame buffers; jumbo-frame configs are rejected instead of silently
  truncating.
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
- A single 802.1Q tag is parsed; non-VLAN bridges drop tagged frames, while
  VLAN-aware bridges enforce per-port PVID/tagged membership.
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
pub const FlowKey = struct {
    zone: u32, proto: u8, src: IpAddr, sport: u16, dst: IpAddr, dport: u16, vlan: u16,
};
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
  The optional `in` selector restricts a rule to one ingress port/interface;
  omitted means any ingress.
- Rewrite destination and reverse state; optional source rewriting for
  hairpin.
- Range mapping `8080-8090:80-90` — v1.1.

### 5.4 R3 implementation notes (current)

- Conntrack uses a single table with both directions mapped to one entry and
  a zone (ingress/egress port id, or a shared bridge zone for bridged SVIs) in
  the key; 64-way sharding is deferred. GC is a 1 s full sweep, cap 65,536
  entries.
- TCP uses flag-based new/established/closing states with SYN 10 s,
  established 300 s and FIN 120 s/RST 10 s timeouts. UDP and ICMP echo use
  30 s; other protocols are not tracked yet.
- SNAT/masquerade applies to TCP, UDP and ICMP echo. The original source port
  is preserved when free; collisions use a deterministic hash/probe from
  1024–65535. Mapping is per flow (endpoint-independent mapping is deferred).
- ICMP echo identifiers are translated. ICMP errors quoting a tracked NAT
  flow are translated on the reverse path: outer and quoted IP addresses and
  L4 ports are restored, and the quoted IP/L4 checksums are adjusted
  incrementally (RFC 1624) so the ICMP payload remains valid.
- Masquerade `out` must resolve to a static interface address. DHCP uplinks
  fail with `InvalidArgument` until R4.
- Fragments and unrelated or non-echo ICMP on an egress with masquerade are
  dropped and counted (`nat_unsupported`) rather than leaking private sources.
  Translated ICMP errors are matched by a separate translated-key index.
- DNAT/port forwarding matches TCP/UDP on a local destination address and the
  configured external port; it rewrites the destination and records a reverse
  key. ICMP port forwards are rejected by validation.
- Hairpin NAT is applied when the DNAT target routes back out the ingress port:
  the source is rewritten to the egress local address and the reply reverses
  both translations. This is the one intentional exception to "never forward
  back out the ingress port".
- Port forwards apply to any local address (the config has no `out` field);
  firewall policy must keep this from shadowing router-local services.
- Checksums are recomputed in full after ordinary NAT rewrites; ICMP-error
  quoted IP/L4 checksums use incremental adjustment because only the quoted
  header is present.

### 5.5 Out of scope

NAT64/464XLAT, ALGs (FTP/SIP/PPTP), SIP/SDP rewriting, deterministic port
preservation across restarts.

## 6. Packet filter

### 6.1 Rules

Ordered, first-match. Implemented match fields: `iif`, `oif` (port, interface
or bridge name), `src`, `dst`, `proto`, `sport`, `dport`, `ct_state`.
Implementing actions: `accept`, `drop`, `reject` (ICMP admin-prohibited).
`mark`, `dscp`, `log`, and NAT actions remain future work.

- Default policy: `inbound: drop`, `forward: drop`, `outbound: accept`
  (configurable; this is a router, not a transparent bridge). The default
  input/forward policies and ordered rules are enforced in the datapath;
  `outbound` policy remains unimplemented and must be `accept`.
  Router-local DHCP/DNS services bypass the input policy.
- Forward rules see the packet after destination NAT and reverse NAT but
  before source NAT; `iif`/`oif` are the original ingress and resolved egress.
- Anti-spoofing: with `rp_filter: true`, a forwarded packet whose source is
  not reachable through the ingress port and VLAN (strict uRPF-lite) is
  dropped.
- Conntrack integration: a conntrack match accepts established/related flows
  when no rule matches; rules may still target them by `ct_state`.
- Stateful by default for TCP/UDP; stateless option per rule is not yet
  exposed in config.
- Control-plane rate limits (`firewall.rate_limit`) are token buckets, one
  second of burst: `icmp` for generated ICMP errors, `arp` for ARP frames and
  `dhcp` for DHCP server requests. `0` disables a limit; excess packets are
  dropped and counted.
- `vnat firewall test` evaluates a synthetic packet against the ordered rules
  offline (same compiler as the datapath) and prints the match.
- `vnatd` rewrites `<run>/<instance>.firewall.json` atomically every 5 s and
  on shutdown with per-rule packet counts and drop/rate-limit aggregates;
  `vnat firewall counters` reads it. Export is best-effort so an unwritable
  run directory never stops forwarding.

### 6.2 Limits

- Rule count cap (4,096) with compile-time validation.
- Runtime counters are a periodic snapshot, not a live stream; a stopped
  daemon leaves the last snapshot in place.
- No L7/app identification, no IPS, no geo-IP.

## 7. DHCPv4 server

- Per downstream interface / subnet.
- Pool, static reservations by MAC or client-id, lease time, renewal/rebind.
- Options: router, DNS, domain, MTU, NTP, lease time, vendor class.
- Conflict detection: ARP probe before offer; handle DECLINE.
- Persisted leases (`/var/lib/vnat/leases.json`), restored on start.
- DHCP relay: out of scope v1.
- DHCPv6/RA: v1.1.

### 7.1 R4 implementation notes (current)

- Implemented: pool allocation, MAC reservations, options 1/3/6/15/26/28/42,
  OFFER/ACK/NAK/DECLINE/RELEASE/INFORM, offer/decline timers and optional
  `lease_db` persistence (atomic JSON, restored on start).
- The server is userspace-only: `vnatd` intercepts UDP/67 on configured ports
  and sends replies through the L2 egress path.
- Not yet implemented: ARP conflict probe before OFFER, client-id lease
  identity, DHCP relay. Initial DHCP client on the uplink is implemented.

## 8. DNS

- Forwarder over UDP (TCP fallback), per-network upstreams.
- Cache respecting TTL, negative caching, max entries.
- Local zone: `vnat.` / `router.vnat.` for status (opt-in).
- Split DNS by domain suffix.
- DoH/DoT: later.
- Serves DHCP-advertised DNS; binds to router addresses only.

### 8.1 R4 implementation notes (current)

- Implemented: UDP listener, upstream pool with per-query retry, positive TTL
  cache, basic negative caching, `max_entries`, SERVFAIL on upstream failure.
- The listener is a kernel UDP socket bound to `dns.listen`; `vnatd` does not
  assign interface addresses itself, so the address must already exist
  (`vnat iface set <dev> <cidr>` or the host network manager).
- Implemented: client TCP listener, upstream TCP fallback, split zones and
  local `vnat.`/`router.vnat.` status zone.
- Not yet implemented: DoH/DoT.

## 9. Control plane

### 9.1 Config

Declarative JSON (versioned, with JSON Schema). Example (the canonical,
machine-checked configs live in `examples/`):

```json
{
  "version": 1,
  "instance": "travel-router",
  "log": { "level": "info", "format": "json" },
  "lease_db": "/var/lib/vnat/leases.json",
  "ports": {
    "uplink":  { "kind": "l2", "device": "wlan0" },
    "lan":     { "kind": "l2", "device": "usb0", "pvid": 10, "tagged": [20],
                 "storm_control": 1000 },
    "vpn0":    { "kind": "l3", "device": "vnat0", "create": "tun", "mtu": 1380 }
  },
  "bridges": {
    "lan-br": { "ports": ["lan"], "vlan_aware": true, "stp": true }
  },
  "interfaces": {
    "lan0": { "bridge": "lan-br", "address": "10.10.0.1/24", "vlan": 10 },
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
    {
      "iface": "lan0",
      "pool": "10.10.0.100-10.10.0.200",
      "lease": "12h",
      "domain": "lan.example",
      "mtu": 1400,
      "reservations": [
        { "mac": "02:00:00:00:00:10", "ip": "10.10.0.50" }
      ]
    }
  ],
  "dns": {
    "upstreams": ["1.1.1.1", "9.9.9.9"],
    "cache": true,
    "listen": "10.10.0.1",
    "max_entries": 1024
  },
  "firewall": {
    "default_in": "drop",
    "default_forward": "drop",
    "rp_filter": true,
    "rate_limit": { "icmp": 100, "arp": 512, "dhcp": 100 },
    "rules": [
      { "action": "accept", "proto": "tcp", "iif": "lan0", "oif": "wan0",
        "src": "10.10.0.0/24", "dport": 443, "ct_state": "new" },
      { "action": "drop", "proto": "icmp", "src": "10.10.0.0/24" }
    ]
  }
}
```

Rules for config:
- `ports.<name>.pvid` and `ports.<name>.tagged` configure VLAN membership on a
  `vlan_aware` bridge; `interfaces.<name>.vlan` selects the SVI VLAN.
- `ports.<name>.storm_control` caps flooded frames per second from that port
  (default 1000, `0` disables).
- `bridges.<name>.stp` enables basic 802.1D root election and port-state
  transitions; it is off by default. With `offload = "kernel"` the kernel runs
  STP instead of the userspace instance.
- `bridges.<name>.offload = "kernel"` enables the Linux kernel bridge backend;
  see §3.3. The backend is Linux-only; startup fails rather than silently
  falling back to userspace.
- `firewall.rules` is evaluated in order before the default policy. Each rule
  may match `proto`, `src`/`dst` CIDRs, `sport`/`dport` (TCP/UDP only),
  `iif`/`oif` (port, interface or bridge name) and `ct_state`, and applies
  `accept`, `drop` or `reject`. `firewall.rate_limit` sets per-second caps for
  generated ICMP errors, ARP and DHCP requests (zero disables).
- Unknown keys are errors (catches typos).
- Version 1 grows by adding *optional* keys in the milestone that implements
  them (R4 DHCP/DNS, R5 VLAN/STP, R6 firewall); existing keys never change
  meaning.
- Validation before any mutation; all-or-nothing apply.
- `vnat up` currently validates the config, starts `vnatd` and waits for the
  control socket; the journaled config diff/apply path remains R7 work. R2
  exposes direct `vnat iface`/`vnat route` verbs. Daemon stderr is written to
  `<state_dir>/vnatd.log` (mode `0600`, truncated when a daemon is launched);
  startup failures print the path and the last 2 KiB of the log.
- Live-reload only for fields marked hot; otherwise restart required.

### 9.1.1 Config field status

- **validated**: parsed and semantically checked.
- **consumed**: used by the running daemon.
- **reserved**: recognized but not implemented; enabling it fails with a
  typed error instead of silently falling back.

Bridge membership, VLAN membership, STP/kernel offload, per-port storm
control, the DHCP client, firewall rules, control-plane rate limits, and
`default_in`/`default_forward` are consumed by the datapath; `default_out`
only accepts `"accept"` until outbound policy is implemented. Explicit
`port_forward` rules are treated as administrator allows and bypass
`default_forward` for the flow they create; ordered `firewall.rules` still
apply first.

### 9.2 CLI

Implemented:

```
vnat validate <config.json>
vnat port list
vnat status [-c] <config.json>
vnat up [-c <config>]
vnat doctor [-c <config>]
vnat nat list [-c <config>]
vnat conntrack list [--state new|established|closing] [--limit <n>] [-c <config>]
vnat iface set|del <dev> <cidr> [-c <config>]
vnat iface up|down <dev> [-c <config>]
vnat route add|del <dst> [via <ip>] dev <dev> [metric <n>] [table <n>] [-c <config>]
vnat down [-c <config>]
vnat journal [-c <config>]
vnat selftest ...
vnat bridge list [-c <config>]
vnat dhcp status
vnat dns query example.com
vnat firewall list [-c <config>]
vnat firewall counters [-c <config>]
vnat firewall test --proto tcp --src 10.0.0.2 --dst 1.1.1.1 --dport 443 [--iif lan0] [-c <config>]
```

`vnat down` refuses while the matching daemon is live; stop `vnatd` first.

Planned with their milestones:

```
vnat bridge create lan                   # R5
vnat nat add masquerade --out wan0       # R3
vnat pcap --iface lan --write cap.pcap   # R9
```

JSON output (`--json`) is planned. Exit codes are stable.

### 9.3 Local API

Implemented (R7 control-socket foundation):

- Unix domain socket (`/run/vnat/control.sock`) under `$VNAT_RUN_DIR`, mode
  `0660`; the socket group is the daemon's primary group, so run `vnatd` and
  the CLI as the intended `vnat` user or adjust ownership during deployment.
  Group-based authorization is not implemented yet.
- One line-delimited JSON request per connection, one response. The CLI opens
  a fresh connection per command; streaming events remain planned.
- One daemon per `$VNAT_RUN_DIR`; a non-blocking advisory lock on
  `<state_dir>/control.sock.lock` is taken before host mutations. A separate
  `<state_dir>/control.sock.up.lock` serializes concurrent `vnat up` starts.
  Use separate run directories for separate instances.
- Operations: `ping`, `status`, `nat.list`, `conntrack.list` (optional
  `state` and `limit`). Responses echo the request `id`; failures return
  `ok:false`, `error_code` and `message`. Each table response also carries the
  daemon `instance` so clients can reject a mismatched `-c` config.
- The server accepts root or the daemon's effective uid and rejects other
  peers with `unauthorized`; until group authorization lands, the effective
  boundary is the peer uid plus socket permissions.
- Snapshots are published by the datapath once per second. NAT rules are
  capped at 64 SNAT + 128 port forwards and conntrack responses at 256 entries
  (the response carries the full table count).
- No TCP listener. v1 exposes no HTTP listener. A post-v1 optional `vnat-web`
  adapter may render this API in a browser; it is an unprivileged client and
  never mutates host state directly (ADR-011).
- Streaming events (planned): `port_up`, `port_down`, `link_change`,
  `dhcp_lease`, `nat_expired`, `error`.

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

`include/vnat.h` is the ABI; `src/ffi.zig` implements it. ABI version 1:

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

Rules:
- Opaque handles, fixed-size status, stable error/event codes, no allocation
  across the boundary.
- Configured existing L3 ports are eligible for fd injection (`kind = "l3"`,
  no `create`). The fd is borrowed and duplicated during `vnat_start`; the
  host may close its copy after startup.
- `vnat_start` blocks until ready; `STARTED` is delivered before it returns.
  `vnat_stop` is idempotent. Events run on the data-plane thread; callbacks
  must not call `vnat_*` functions other than `vnat_get_status`.
- The FFI profile disables host mutations and hotplug monitoring. It uses the
  host's pthread implementation rather than Zig's raw-clone thread path.
- ADR-010 records the ownership, threading and compatibility contract.

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

- GUI / web UI / TUI beyond `status --watch` (local web admin deferred to
  post-v1, ADR-011).
- Overlay/P2P/VPN protocols (future uplink port).
- Dynamic routing protocols.
- IPv6 RA/DHCPv6 (v1.1), NAT64.
- ALGs, captive portal, 802.1X, QoS shaping.
- macOS/Windows.
- Clustering/HA.
