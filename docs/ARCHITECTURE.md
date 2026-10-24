# vNAT — Architecture

> Router-first design. The overlay/P2P work from the earlier draft is deferred
> to a future uplink module (ADR-004); the engine described here is the product.
> Scope: [CORE-SCOPE.md](./CORE-SCOPE.md). Plan: [PLAN.md](./PLAN.md).

## 1. Principles

1. **The core is the router.** Bridging, routing, NAT, DHCP, DNS and filtering
   live in Zig and do not depend on `iptables`/`nft`/`netd` being present.
2. **Ports, not interfaces-as-strings.** Everything is a `Port` with typed
   capabilities; platform code only opens ports and applies host mutations.
3. **Userspace reference, kernel fast path.** Correctness is defined by the
   userspace pipeline; kernel offloads are optional accelerators selected by
   config.
4. **Control plane / data plane split.** The data plane never blocks on the
   control plane; config changes are compiled to immutable routing/bridge/NAT
   tables and swapped atomically.
5. **Journal before mutation.** Every host change has a recorded inverse.
6. **No GUI in v1, one API.** CLI and a Unix-socket API are the only v1
   interfaces; the C ABI is for hosts (Android). A post-v1 optional `vnat-web`
   adapter is an unprivileged client of the same API (ADR-011).
7. **Hostile input.** Decoders are bounds-checked and fuzzed; no `unreachable`
   on wire data.

## 2. Repository layout

```
vnat/
├── build.zig
├── build.zig.zon
├── AGENTS.md
├── docs/
│   ├── PRODUCT.md
│   ├── CORE-SCOPE.md
│   ├── ANDROID.md
│   ├── ARCHITECTURE.md
│   ├── PLAN.md
│   ├── RESEARCH.md
│   ├── SOURCES.md
│   └── adr/
├── src/
│   ├── lib.zig                  public Zig API
│   ├── ffi.zig                  C ABI (R7)
│   ├── thread.zig               std/pthread thread backend
│   ├── io.zig                   std.Io wiring, timers, cancellation
│   ├── log.zig                  leveled text/JSON logger
│   ├── types.zig                PortId, Mac, IpAddr, Mtu, VlanId
│   ├── app/
│   │   └── service.zig           shared daemon/FFI lifecycle
│   ├── config/
│   │   ├── schema.zig           typed config model
│   │   ├── parse.zig            strict JSON parser
│   │   └── validate.zig         references, subnets, conflicts
│   ├── port/
│   │   ├── port.zig             Port vtable, PortInfo, Stats
│   │   ├── manager.zig          config → ports, hotplug pump
│   │   ├── pool.zig             buffer pools
│   │   ├── memory.zig           in-memory port for tests
│   │   ├── fd.zig               host-injected L3 port
│   │   ├── linux/
│   │   │   ├── sys.zig          non-blocking fd helpers, errno mapping
│   │   │   ├── iface.zig        SIOCGIF* control ioctls
│   │   │   ├── af_packet.zig    L2 port (TPACKET_V3 later)
│   │   │   ├── tun.zig          TUN (IFF_NO_PI) and TAP
│   │   │   └── netlink.zig      link dump + link/addr/neigh monitor
│   │   └── android/             R7/R8: VpnService fd, raw, JNI
│   ├── l2/
│   │   ├── ethernet.zig         Ethernet II + 802.1Q parse/build (R2)
│   │   ├── bridge.zig           FDB, flooding, aging
│   │   ├── vlan.zig             PVID/trunk/filtering
│   │   └── stp.zig              optional 802.1D
│   ├── l3/
│   │   ├── ipv4.zig             header, checksum, TTL (R2)
│   │   ├── ipv6.zig             header, extension parsing
│   │   ├── fib.zig              LPM (flat R2, trie R3)
│   │   ├── rib.zig              route sources + policy rules
│   │   ├── arp.zig              cache + request/reply (R2)
│   │   ├── ndp.zig              neighbor cache (v1.1 RA)
│   │   ├── icmp.zig             errors + echo (R2)
│   │   ├── forward.zig          IPv4 forwarding, L2 + TUN ingress (R2)
│   │   └── mtu.zig              MSS clamp, PMTU errors
│   ├── nat/
│   │   ├── conntrack.zig        5-tuple table, timeouts, GC, port allocator (R3)
│   │   ├── nat.zig              SNAT/DNAT rewrite, ICMP-error checksum adjust (R3)
│   │   └── checksum.zig         incremental checksum updates (planned)
│   ├── services/
│   │   ├── dhcp/message.zig     wire parser/builder
│   │   ├── dhcp/server.zig      pool, reservations, options, DECLINE
│   │   ├── dhcp/leases.zig      atomic JSON lease persistence
│   │   ├── dhcp/client.zig      uplink (planned)
│   │   └── dns/                 message, cache, UDP forwarder
│   ├── firewall/
│   │   ├── rules.zig            ordered rules, match/actions
│   │   └── compile.zig          rule set → fast matcher
│   ├── control/
│   │   ├── server.zig           unix socket, JSON lines (R7)
│   │   ├── commands.zig         CLI verbs → core operations (R7)
│   │   ├── journal.zig          JSONL forward ops, ownership, rollback (R2)
│   │   ├── host.zig             iface/route mutations + journal (R2)
│   │   ├── offload.zig          kernel bridge plan + veth trunk (R5, Linux)
│   │   └── events.zig           event bus
│   ├── web/                     POST-V1: HTTP, templates, auth (ADR-011)
│   └── overlay/                 FUTURE: uplink overlay (ADR-004)
├── exec/
│   ├── vnat/main.zig            CLI (`validate`, `port`, `status`, `iface`, `route`, `down`, `journal`, `selftest`)
│   ├── vnatd/main.zig           daemon (config, netlink, IPv4 forwarding loop)
│   └── vnatweb/main.zig         POST-V1: unprivileged web admin (ADR-011)
├── include/vnat.h
├── test/
│   ├── unit/
│   ├── netns/                   Linux topologies
│   ├── fuzz/
│   └── interop/
└── scripts/
    ├── build_android.sh
    ├── test_netns.sh
    ├── test_route.sh
    ├── test_journal.sh
    ├── test_offload.sh
    ├── nat_matrix.sh
    └── perf.sh
```

## 3. Core interfaces

### 3.1 Port

```zig
pub const PortId = enum(u32) { _ };

pub const PortKind = enum { ethernet, wifi, cellular, usb, tun, tap, bridge, memory };

pub const Capabilities = struct {
    l2: bool,
    l3: bool,
    promiscuous: bool,
    multicast: bool,
    vlan_filter: bool,
    checksum_offload: bool,
    gso: bool,
    can_set_mtu: bool,
};

pub const Frame = struct {
    port: PortId,
    data: []u8,
    len: u32,
    vlan: ?u16,
    offload: Offload,
};

pub const Port = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read:  *const fn (ctx: *anyopaque, io: std.Io, buf: []u8) anyerror!usize,
        write: *const fn (ctx: *anyopaque, io: std.Io, frame: []const u8) anyerror!void,
        info:  *const fn (ctx: *anyopaque) PortInfo,
        set_up: *const fn (ctx: *anyopaque, io: std.Io, up: bool) anyerror!void,
        set_mtu: *const fn (ctx: *anyopaque, io: std.Io, mtu: u16) anyerror!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };
};
```

- `read`/`write` are the only hot-path calls.
- `PortInfo` carries name, ifindex, mac, mtu, link state, speed, counters.
- L2 vs L3 is a capability; the pipeline asserts the frame type matches.

### 3.2 Data-plane pipeline

```
ingress port
   │  parse L2 (if L2)
   ▼
[ bridge lookup ]──hit──▶ egress port (L2)
   │ miss / routed port
   ▼
[ L3 parse: IPv4/IPv6 ]
   ▼
[ conntrack lookup ]──established──▶ NAT reverse + FIB
   │ new
   ▼
[ firewall: prerouting ]
   ▼
[ DNAT (port forward) ]
   ▼
[ FIB lookup ]──no route──▶ drop/ICMP
   ▼
[ firewall: forward ]
   ▼
[ SNAT (masquerade) ]
   ▼
[ TTL/hop decrement, checksum, MSS clamp ]
   ▼
egress port write
```

- Tables (`BridgeTable`, `Rib`, `NatTable`, `RuleSet`) are immutable snapshots
  swapped by the control plane; workers read the current pointer (RCU-style
  with epoch reclamation).
- Per-port ingress queues; a worker owns a set of ports (no cross-thread
  packet handoff on the fast path).

**R2 status.** The implemented path is Ethernet (L2) or bare IPv4 (TUN) →
ARP/IPv4 → FIB → TTL/MTU → neighbor cache/pending queue → egress. It generates
ICMP errors, writes bare IP back to TUN ports, and repairs TCP/UDP checksums
in software (ADR-007). R3 adds conntrack before routing, DNAT before the FIB,
reverse translation for replies (including replies addressed to a local NAT
IP), and SNAT after the FIB/MTU checks. Hairpin flows SNAT back out the ingress
port. Bridge, firewall and MSS clamping are not yet in the loop.

### 3.3 Bridge

```zig
pub const Bridge = struct {
    id: BridgeId,
    ports: []PortId,
    vlan_aware: bool,
    stp: bool,
    fdb: Fdb,          // (vlan, mac) → port, aging
};
```

- Learning on ingress, lookup on egress.
- Flood set precomputed per VLAN.
- Optional kernel offload (`bridge.offload = "kernel"`): `control/offload.zig`
  creates one kernel bridge and a veth trunk per bridge, enslaves the physical
  members, and opens the trunk peer as the bridge's only synthetic port.
  Userspace bridging, SVIs, routing, NAT, DHCP and firewall keep working on
  that synthetic port; kernel STP replaces userspace STP when enabled.

### 3.4 Router / FIB

```zig
pub const Route = struct {
    dst: IpPrefix,
    via: ?IpAddr,
    dev: PortId,
    metric: u32,
    source: RouteSource, // connected | static | dhcp | kernel
    table: u32,
};

pub const Fib = struct {
    pub fn lookup(self: *const Fib, dst: IpAddr, mark: u32) ?NextHop;
};
```

- IPv4/IPv6 compressed trie; O(prefix bits).
- Policy rules: ordered `(from, iif, mark) → table`.
- Connected routes generated from interface addresses; removed on port loss.

### 3.5 NAT / conntrack

```zig
pub const CtEntry = struct {
    key: FlowKey,
    reply_key: FlowKey,
    state: FlowState,
    proto_state: ProtoState, // TCP FSM
    nat: ?NatInfo,           // snat/dnat applied
    timeout: i64,
    counters: Counters,
};
```

- R3 uses one `Conntrack` table with both directions mapped to the same entry
  and the ingress/egress port as the zone; the data plane is single-threaded.
  Sharding/epoch reclamation is deferred.
- GC is a 1 s full sweep with a 65,536-entry cap; exhausted tables drop new
  flows and increment counters. Entries are not yet evicted on port teardown.
- SNAT allocation preserves the source port when free, otherwise hashes and
  probes 1024–65535. Ports are released by GC.
- NAT rewrites recompute IPv4/TCP/UDP/ICMP checksums from scratch (ADR-005
  allows this); incremental updates are an R3 optimization.
- DNAT/port forwarding and hairpin are implemented for TCP/UDP; ICMP port
  forwards are rejected. ICMP errors quoting a tracked NAT flow are translated
  (outer and quoted tuple, RFC 1624 quoted-L4 checksum adjustment); fragments
  and unrelated or non-echo ICMP on a SNAT egress are dropped and counted.

### 3.6 Services

- DHCP server is a state machine per interface, backed by a persisted lease DB.
- DNS forwarder has its own cache and upstream pool; no blocking on the
  forwarding path (async requests with timeouts).
- Both are optional modules; the router works without them.

### 3.7 Control plane

```
CLI / API ──▶ config::diff ──▶ mutation list ──▶ journal ──▶ apply
                                                   │
                                                   └──▶ event bus
```

- `config::diff` compares desired vs current compiled state; produces ordered
  mutations (remove dependents before parents, add parents before children).
- `apply` is transactional: on failure, replay the inverse of already-applied
  mutations and return a typed error.
- Hot-reload fields: routes, NAT rules, firewall rules, DNS upstreams.
  Restart-required: ports, bridges, addresses.
- Events: `port_up/down`, `link_change`, `addr_change`, `dhcp_lease`,
  `nat_expired`, `config_applied`, `error`.
- Post-v1, an optional `vnat-web` adapter may expose this API over
  authenticated HTTP. It remains an unprivileged client of the Unix socket and
  never mutates host state directly (ADR-011).

## 4. Datapath backends

| Backend | Where | When | Trade-off |
|---|---|---|---|
| `userspace` | Linux, Android root | Default; portable | CPU-bound, full control |
| `kernel_bridge` | Linux | `bridge.offload=kernel` | Fast L2 via kernel bridge; routed traffic crosses a veth trunk |
| `kernel_nat` | Linux/Android root | `nat.offload=kernel` | Fast NAT via nft/iptables, control-plane only |
| `nfqueue` | Android root (experimental) | `intercept=nfqueue` | Userspace control of tethered traffic, slower |
| `proxy` | Android VPN mode | No raw uplink; sockets only | Works unrooted, TCP/UDP proxy NAT |

Selection is a config policy, not a runtime guess. The core refuses to start
if the requested backend is unavailable, with an actionable error (never a
silent fallback).

## 5. Threading model

**v1: `Io.Threaded` with per-port workers.**

```
main thread ── control plane, signals, journal
   │
   ├── port worker A: read(port) → pipeline → write(egress)
   ├── port worker B: ...
   └── timer thread: conntrack GC, DHCP lease expiry, DNS cache
```

- One worker per port (or per queue on multi-queue TUN/AF_PACKET).
- No packet handoff between workers; a packet is fully processed by the
  ingress worker.
- Shared state is immutable snapshots (FIB, rules) + sharded mutable tables
  (conntrack, FDB, ARP) with per-shard locks.
- Backpressure: bounded ingress queues; drop-oldest or drop-tail with counters.
- `Io.Threaded` gives task concurrency and cancellation when built with
  threads; use `io.async` for timers/control operations.

Post-v1: custom epoll/kqueue reactor or AF_XDP for > 5 Gbps.

## 6. Platform backends

### 6.1 Linux

| Concern | API |
|---|---|
| L2 port | `AF_PACKET` + `PACKET_MMAP`/TPACKET_V3 |
| L3 port | `/dev/net/tun` + `TUNSETIFF` |
| Addresses/routes/neighbors | rtnetlink |
| Link events | rtnetlink multicast groups |
| MTU/speed | netlink/ethtool |
| Kernel bridge | netlink (`RTM_NEWLINK` with `IFLA_MASTER`) |
| Kernel NAT | nftables (netlink) preferred; iptables fallback |
| DNS host config | resolv.conf / systemd-resolved (optional, opt-in) |
| Namespaces | `setns` for tests and container deployments |

Privileges: `CAP_NET_ADMIN` + `CAP_NET_RAW`; drop everything else. Provide a
systemd unit with `AmbientCapabilities`.

### 6.2 Android

| Mode | Backend |
|---|---|
| VPN (no root) | `fd_port` (VpnService fd) + proxy NAT over protected sockets |
| Root | `raw.zig` (`AF_PACKET`) + `tun.zig` + `netlink` + kernel/nfqueue interception |

Host app responsibilities and lifecycle are in [ANDROID.md](./ANDROID.md).

### 6.3 Future (macOS/Windows)

Design for it now: `Port` vtable, `HostOps` trait (routes, addresses, DNS),
and no `if (os == ...)` in the core. macOS: utun/BPF, PF_ROUTE, pf. Windows:
Wintun/Npcap, IP Helper, WFP/New-NetNat.

## 7. Configuration and journal

- Strict schema, versioned; unknown keys rejected.
- Validation is pure (no side effects) and runs before apply.
- R2 journal: `$VNAT_RUN_DIR/<instance>.journal` (default `/run/vnat`),
  one forward op per JSON line, fsynced and atomically replaced before the
  netlink mutation. `vnat down` derives inverses in reverse order; deletes are
  gated by journal ownership; a failed apply removes its record.
- The R7 control socket, read-only status, `vnat doctor` diagnostics, and the
  run-dir daemon lock are implemented. Pending/applied reconciliation and
  batch apply remain.
- Secrets (if any) come from env/file descriptors, never the config file.

## 8. Security

- Control socket is `0660` owned by the daemon uid and primary group; server
  authorization currently accepts root or that uid. No TCP listener.
- Privilege separation option (post-v1): privileged datapath helper +
  unprivileged control process, communicating over a socketpair.
- Firewall default-deny for inbound/forward.
- Anti-spoofing: drop packets whose source is not reachable via the ingress
  port (uRPF-lite) when `firewall.rp_filter = true`.
- Rate limits: ICMP errors, ARP, DHCP, DNS.
- No packet payload logging by default; `pcap` is explicit and time-boxed.
- Root journal is integrity-checked on replay (no shell interpolation).

## 9. Performance

Performance targets are deferred to R9. `scripts/perf.sh` is a smoke test only;
no throughput or latency claim is made before R9.

- Batch reads/writes (`recvmmsg`/`sendmmsg`, AF_PACKET rings).
- Per-core buffer pools; no allocation in `read → forward → write`.
- Checksums: software, vectorized; offload only when negotiated.
- Sharded conntrack (`2^n` shards by hash) to avoid a global lock.
- FIB snapshot swap, no locks on lookup.
- Optional `kernel_nat`/`kernel_bridge` for line-rate paths.
- Profiling hooks: per-stage cycle counters, drop reasons, queue depth.

## 10. Testing

| Layer | Approach |
|---|---|
| Parsers | Unit + fuzz (Ethernet, VLAN, IPv4/6, TCP/UDP, DHCP, DNS) |
| Tables | Property tests for FIB/LPM and conntrack |
| Pipeline | In-memory ports with golden packet vectors |
| Topology | Linux netns + veth + TUN (`scripts/test_netns.sh`) |
| Forwarding | Two-host netns ping + TCP (`scripts/test_route.sh`) |
| TUN | Kernel TUN peer ↔ veth host, ICMP + TCP (`scripts/test_tun.sh`) |
| Journal | iface/route mutations + `vnat down` (`scripts/test_journal.sh`) |
| NAT/conntrack | SNAT UDP/ICMP/TCP, DNAT/hairpin (`scripts/nat_matrix.sh`) |
| NAT matrix | Emulated EIM/EDM, hairpin, port-forward, exhaustion |
| DHCP/DNS | Client emulators; lease persistence across restart |
| Security/privilege | Journal rollback, default-deny policy, netns isolation |
| Crash safety | kill -9, reboot simulation, `vnat doctor` |
| Android | Emulator (VPN mode), rooted device (root mode) |
| Performance | `iperf3`, `pktgen`, 64 B and 1500 B, multi-flow |

## 11. ADRs

| ADR | Decision |
|---|---|
| [001](adr/001-router-first.md) | Router-first product scope |
| [002](adr/002-hybrid-datapath.md) | Userspace reference + kernel fast path |
| [003](adr/003-android-capability-tiers.md) | Android VPN + root router tiers |
| [004](adr/004-overlay-deferred.md) | Overlay/P2P deferred to a future uplink module |
| [005](adr/005-conntrack-nat.md) | Conntrack/NAT design (port allocation, timeouts) |
| [006](adr/006-config-journal.md) | Config schema and R2 journal format |
| [007](adr/007-userspace-checksum-repair.md) | Repair transport checksums on forwarded IPv4 |
| [008](adr/008-userspace-stp.md) | Optional userspace 802.1D STP |
| [009](adr/009-kernel-bridge-offload.md) | Kernel bridge offload with a veth trunk |
| [010](adr/010-embedded-c-abi.md) | Embedded C ABI and host fd injection |
| [011](adr/011-web-admin.md) | Optional local web admin (post-v1) |
