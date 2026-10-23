# vNAT — Knowledge Base

> Compiled 2026-10-22. Sources: local `~/Documents/SoftEtherVPN` (commit `f20c61a`),
> GitHub `devstroop/SoftEtherVPN` (now `devstroop/SE`, HEAD `8f6d657`),
> `vnt-dev/vnt`, Zig 0.16.0/0.17.0 release notes, Tailscale NAT-traversal
> write-up, Wintun docs, Anthropic `skills` repo.
> See [SOURCES.md](./SOURCES.md) for URLs.

> **Scope note (2026-10-22, second planning round).** The product is now a
> **portable virtual router** (Linux + Android) — see
> [PRODUCT.md](./PRODUCT.md), [CORE-SCOPE.md](./CORE-SCOPE.md) and
> [ADR-001](./adr/001-router-first.md). Sections 1–2 (SoftEther/VNT prior art),
> 4 (platform APIs), 5 (Zig), 6–10 (protocol, security, performance, testing)
> remain directly relevant. Section 3 (NAT traversal / STUN / TURN / relay) is
> **deferred** to the future overlay uplink (ADR-004); it is retained because
> the design is reusable and the research is done.

---

## 0. What "vNAT" can mean — scope decision

Three distinct meanings exist in the wild:

| Meaning | Description | Fit for this project |
|---|---|---|
| **Virtual Network Address Translation** (academic, Columbia 2002) | Virtualizes transport connections so a live TCP connection survives host migration | Niche; mostly a research artifact |
| **Virtual NAT** (enterprise NFV) | A VNF that instantiates micro-NAT instances | Telco-oriented; not a product for devices |
| **Overlay / P2P virtual network with a NAT gateway** | Devices join a virtual L2/L3 network, get virtual IPs, reach each other and the internet through a virtual NAT | **Matches the SoftEtherVPN lineage and the Linux+Android→macOS+Windows target list** |

**Working definition for planning (updated):**
> vNAT is a cross-platform, Zig-native **portable virtual router**. It attaches
> directly to L2/L3 interfaces, bridges or routes between them, and provides
> NAT, DHCP, DNS, firewall and port forwarding. An overlay/P2P transport is a
> future uplink port, not the core.

This subsumes "virtual NAT" and "P2P VPN" while making the router the product.
See [ADR-001](./adr/001-router-first.md) and [PRODUCT.md](./PRODUCT.md).

---

## 1. Prior art #1 — SoftEtherVPN Zig port (our own codebase)

### 1.1 Shape of the codebase

- **130 Zig files, ~86,075 LOC**, `minimum_zig_version = "0.16.0"`.
- Four executables: `vpnclient`, `vpnserver`, `vpncmd`, `vpnbridge`.
- Shared/static library with **92 C ABI exports** (`src/ffi.zig`) used by
  Flutter / Swift / Kotlin hosts.
- One external C dependency: **OpenSSL 3.x** (TLS only). zlib is bundled.
  Session crypto is pure Zig.

Layering (mirrors upstream SoftEther's `Mayaqua` / `Cedar` split):

```
src/
├── cedar/        VPN protocol + client + server
│   ├── client/   VpnClient facade, connection pool, auth handshake, state machine
│   ├── server/   hub, listener, accept, DHCP/NAT/SecureNAT, farm, admin RPC/WPC
│   ├── protocol/ Pack serialization, RPC, auth, tunnel framing, watermark
│   ├── session/  AES-256-CBC session encryption, key derivation, RC4, MD4
│   └── tunnel/   ARP, DHCP, DHCPv6, data loop, session I/O
├── mayaqua/      platform abstraction
│   ├── encrypt/  pure-Zig SHA-0, SHA-1/256, AES-256-CBC, RC4, MD4
│   ├── kernel/   IpAddress, MacAddress, IP parsing, errors
│   └── network/  sockets, OpenSSL TLS (connect + accept), HTTP, SOCKS5,
│                 DNS cache, UDP acceleration (RUDP)
├── adapter/      TUN/TAP/BPF/AF_PACKET/Npcap + routing + DHCP client
├── bridge/       L2 bridge + STP 802.1D
├── cli/          args, config store, interactive shell, display
├── app/          lifecycle, daemon, signals
└── exec/         executables
```

### 1.2 NAT engine (`src/cedar/server/nat.zig`, 1,597 lines)

This is the most directly reusable design for vNAT's NAT component.

**Model:** outbound-only, **socket-per-flow** NAT. It does *not* implement a
userspace TCP/IP stack; for each flow it opens a real OS socket and splices
payloads. This is a proxy-NAT, not a packet-level NAT.

Constants (mirroring C `Virtual.h` / `Nat.c`):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_NAT_ENTRIES` | 65,536 | NAT table cap |
| `NAT_TCP_TIMEOUT_MS` | 300,000 | TCP flow idle timeout |
| `NAT_UDP_TIMEOUT_MS` | 30,000 | UDP flow idle timeout |
| `NAT_ICMP_TIMEOUT_MS` | 30,000 | ICMP flow idle timeout |
| `NAT_SWEEP_INTERVAL_MS` | 1,000 | GC sweep cadence |
| `NAT_TCP_CONNECT_TIMEOUT_MS` | 10,000 | Outbound connect timeout |
| `NAT_MAX_CONNECT_QUEUE` | 256 | Pending connects |

Flow key = `(proto, src_ip, src_port, dst_ip, dst_port)`; status enum
`connecting | established | closing | active`. Public-IP cache avoids a
syscall per packet.

**SecureNAT orchestrator** (`securenat.zig`, 483 lines) wires three pieces:

```
hub outbound queue
      │
      ├─ ARP  → VirtualHost (virtual host 192.168.30.1, ARP responder)
      ├─ DHCP → DhcpServer (pool 192.168.30.10–200)
      └─ IPv4 → NatEngine (per-flow outbound sockets)
                     │
                     └─ responses → Hub.storePacket()
```

Default virtual network: `192.168.30.1/24`, DNS `192.168.30.1` + `8.8.8.8`,
1 s polling loop. The polling thread owns sub-component state; the hub mutex
guards queues.

**Limitations to fix in vNAT:**
- No inbound port mapping (was deferred; VNT has it).
- No full TCP/IP stack → cannot terminate arbitrary IP protocols or do
  packet-level NAT without a real socket.
- No NAT64/NAT46, no hairpinning, no UPnP/NAT-PMP/PCP.
- No port-preservation guarantees.

### 1.3 UDP acceleration / RUDP (`src/mayaqua/network/udp_accel.zig`, 647 lines)

- NAT-T probe sets up a bidirectional UDP path, falls back to TCP.
- Wire format: `[flags 1][IV 16][AES-128-CBC ciphertext][HMAC-SHA1 20]`.
- Sequence numbers detect duplicates/replay.
- **Documented gaps (RCA-03):** no STUN-style address discovery, no port
  prediction, no differential NAT-type behavior, no re-probe after failure,
  HMAC key derived as `SHA1(AES key)` (weak), and `performHandshake()` passes
  `null` bulk keys so the feature was silently off for that path.

> This RCA is effectively the requirements document for vNAT's transport.

### 1.4 Platform adapters — concrete API knowledge

| Platform | File | Mechanism | Key details |
|---|---|---|---|
| Linux | `adapter/tun_linux.zig` | `/dev/net/tun` | `TUNSETIFF` `0x400454ca`, `IFF_TUN 0x0001`, `IFF_TAP 0x0002`, `IFF_NO_PI 0x1000`; `TUNSETPERSIST 0x400454cb`, `TUNSETOWNER 0x400454cc`; ifreq ioctls `SIOCSIFMTU/SIOCSIFADDR/SIOCSIFNETMASK/SIOCSIFFLAGS`; MTU 1500; needs root or `CAP_NET_ADMIN` |
| Linux L2 | `adapter/af_packet.zig` | `AF_PACKET` | raw Ethernet; needs root or `CAP_NET_RAW` |
| macOS | `adapter/utun.zig` | kernel control socket | `AF_SYSTEM 32`, `AF_SYS_CONTROL 2`, `SYSPROTO_CONTROL 2`, `CTLIOCGINFO 0xC0644E03`, control name `com.apple.net.utun_control`, `UTUN_OPT_IFNAME 2`; **4-byte address-family header** (`AF_INET 2` / `AF_INET6 30`) on every read/write; `MAX_UTUN_UNITS 16`; MTU 1500, buffer 2048 |
| macOS L2 | `adapter/bpf.zig` | BPF | `/dev/bpf*`, ioctl config, read/write with buffering |
| Windows | `adapter/tap_windows.zig` | Wintun (preferred) / TAP-Windows6 | runtime `LoadLibraryEx` + `GetProcAddress`; `WintunCreateAdapter`, `WintunStartSession`, `WintunReceivePacket`, `WintunReleaseReceivePacket`, `WintunAllocateSendPacket`, `WintunSendPacket`, `WintunGetReadWaitEvent`, `WintunGetAdapterLUID`; requires admin |
| Mobile | `adapter/fd_adapter.zig` | injected fd | Android `VpnService.Builder.establish()` fd / iOS `NEPacketTunnelProvider`; **direct synchronous writes, no ring buffer** (documented latency/drop rationale) |

Routing (`adapter/route.zig`, 1,115 lines): default gateway discovery,
add/delete route (IPv4 + IPv6), DNS configuration, macOS network-service
lookup, and `route_heal.zig` cleans stale routes after crashes.

### 1.5 Hard-won lessons

- **Mobile fd tuning:** a second queue (ring buffer + writer thread) makes
  drops bursty and worsens TCP retransmit storms. Direct non-blocking writes
  distribute drops per-packet and are TCP-friendly. Android TUN buffer is
  ≥ 64 KiB; iOS socketpair buffers are raised to 4 MiB by the host.
- **Android ABI mismatch** (`aarch64` vs `arm`) causes `SIGSEGV` in
  `DynamicLibrary.open()`.
- **macOS privilege:** `utun` requires root; the project ships a SUID helper
  (`utun_escalate.zig`, `utun_helper_main.zig`) with `chown root:wheel` +
  `chmod u+s`.
- **OpenSSL cross-compilation** is the biggest build tax: Homebrew paths,
  arm64 vs x86_64, pre-built iOS/Android trees committed under `deps/`.
- **Stale `zig-out/`** after ABI changes produces confusing mismatches.
- **Version skew** between host app and embedded lib is a recurring failure
  mode — pin the ABI.

---

## 2. Prior art #2 — VNT (Rust, closest product analog)

`vnt-dev/vnt` — "efficient VPN" for site-to-site LAN over the internet.
~30k LOC in `vnt-core`; desktop (Tauri), CLI, web, JNI, Android.

### 2.1 Product model

- Join a virtual network with **network code (`-k`)** + **server (`-s`)**.
- Server assigns virtual IPs (default `10.26.0.x`), acts as **rendezvous +
  relay**.
- Peers try **P2P** first; fall back to **server relay** or **client relay**.
- Optional password → **end-to-end ChaCha20-Poly1305**; server only sees
  ciphertext.
- Server link itself is encrypted: **TCP-TLS / QUIC / WSS**, optional cert
  pinning.
- Modes: `no` (no adapter), `tun` (L3), `tap` (L2); IPv4 interop across modes.
- Virtual IPv6: `fd76:6e74::/96`, last 32 bits = virtual IPv4 node ID
  (e.g. `10.26.0.2` → `fd76:6e74::a1a:2`).
- Extras: port mapping, subnet mapping, IP proxy (point-to-point / point-to-net),
  broadcast/multicast, FEC, LZ4, multi-channel UDP for QoS, multi-server
  failover, server-less mode with `peer_address` seeds + gossip.

### 2.2 Module map worth copying

```
vnt-core/src/
├── context/{mod,config,nat}.rs      config + NAT info + punch backoff
├── tunnel_core/{outbound,p2p,server}
│   ├── p2p/{inbound,route_table,transport/task}
│   ├── server/{inbound,outbound,connection_manager}
├── protocol/{control,client,rpc,transmission}
├── tun/{general,enhanced_tun,sender}
├── nat/{subnet_mapping,subnet_packet}
├── port_mapping/{tcp,udp}
├── crypto/{chacha20_poly1305}
├── fec/{encoder,decoder}
├── compression/lz4
├── tls/{cert,verifier}
└── network_info, system_subnet_routes, dns_query, device_id
```

### 2.3 NAT/punch design

`context/nat.rs` tracks `NatInfo` (type, public IPs, public UDP/TCP ports,
local IPs/ports, IPv6) and emits **identity-level change** events (network
switch / NAT reboot). Symmetric-NAT port churn is deliberately *not* treated
as identity change. `PunchState` / `PunchBackoff` rate-limit punching per
peer IP with exponential backoff and a reset on NAT change.

The heavy lifting lives in the `rustp2p-core` crate (`NatType`, `NatInfo`,
punch scheduler). Port this concept, not the code.

### 2.4 Android integration (battle-tested)

- Native library is driven by the host `VpnService`:
  1. `createNetwork(config)` → server registration → assigned CIDR.
  2. `establishVpnInterface(cidr, mtu, routes)` → `ParcelFileDescriptor.detachFd()`.
  3. `network.startTun(fd)`.
  4. Loop on `nextEvent()`; on runtime change either apply in place or
     rebuild the interface and pass the new fd.
- **MTU 1380** is the default (VPN overhead).
- `addAddress` does **not** create a route: must `addRoute(network, prefix)`
  explicitly.
- Do **not** add `0.0.0.0/0` unless full-tunnel is intended; otherwise normal
  internet traffic is hijacked into the TUN.
- Virtual IPv6 also needs explicit `addAddress` + `addRoute("fd76:6e74::", 96)`
  + `addRoute("ff00::", 8)`.
- Runtime changes carry `needsVpnRebuild` / `needsInstanceRebuild` flags.

### 2.5 Windows integration

- TUN via `wintun.dll` (ships 0.14.1, amd64/arm64/x86).
- TAP mode requires admin + `tap-windows` (hardware ID `tap0901`).
- Admin required to create the adapter.

---

## 3. NAT fundamentals (the physics vNAT must handle)

### 3.1 Stateful firewall + SNAT

A NAT is a stateful firewall plus source-address/port rewriting. For UDP the
rule is: *an inbound packet is allowed if a matching outbound packet was seen
first*. Therefore both peers must send first — simultaneous transmission
("hole punching") works because the firewall only checks `(src, dst)` tuple
correspondence, not payload relationship.

### 3.2 NAT mapping taxonomy (RFC 4787)

```
                     firewall: endpoint-independent   endpoint-dependent (IP+port)
mapping EIM          Full Cone                        (theoretical)
mapping EDM          Restricted / Port-Restricted      Symmetric
```

Practical simplification:

- **Easy NAT** = Endpoint-Independent Mapping (EIM). Public port is stable
  regardless of destination.
- **Hard NAT** = Endpoint-Dependent Mapping (EDM) = Symmetric. Public port
  changes per destination.

The only distinction that matters for traversal code is **EIM vs EDM**.

### 3.3 STUN / TURN / ICE

- **STUN** (RFC 8489): ask a server "what public `ip:port` did you see me
  from?". Must be sent from the *same socket* used for the data path, because
  each socket gets a different mapping.
- **TURN** (RFC 8656): relay allocation; fallback when direct fails.
  Authenticated, stateful, bandwidth-heavy.
- **ICE** (RFC 8445): framework that gathers candidates (host, server-reflexive,
  relay), pairs them, and tests connectivity. WebRTC's model.
- **DERP** (Tailscale): HTTP-based encrypted relay, doubles as signalling.
  Simpler than TURN, no open-server interop.

### 3.4 Hard-NAT tricks

- **Birthday-paradox port probing:** open ~256 sockets on the hard side, probe
  random destination ports from the easy side. ~50% in ~174 probes, ~98% in
  ~1,024 probes at 100 pps. Two hard NATs → search space squares; needs
  ~170k probes/side for 99.9%, so usually not worth it.
- **Port mapping protocols:** UPnP IGD (SOAP/XML, ubiquitous but insecure
  history), NAT-PMP (RFC 6886, simple), PCP (RFC 6887, v2). All break under
  double NAT.
- **Hairpinning:** same-CGNAT peers may need the NAT to turn packets around.
  Often broken; detect and fall back.
- **Keepalive:** UDP mapping expires (commonly ~30 s); send keepalives or use
  an out-of-band re-open.

### 3.5 IPv6

- No NAT in the classic sense, but stateful firewalls still exist.
- Prefer IPv6 when both peers have global addresses (often direct connectivity).
- Beware NAT64/DNS64 (464XLAT), prefix delegation churn, and IPv6-only mobile
  networks — need NAT64 synthesis or relay.
- Dual-stack happy-eyeballs: race v4 and v6, prefer lowest RTT.
- Virtual IPv6 addressing (VNT pattern) is a clean way to give every node a
  stable `fd00::/8` ULA regardless of underlay.

### 3.6 Why UDP, and when QUIC

- NAT traversal needs raw socket control and extra probe packets → UDP.
- If you want streams, use **QUIC over UDP**; don't try TCP hole punching
  unless you must (RFC 5382; simultaneous open is fragile and middlebox-hostile).
- TCP-only networks (UDP blocked) need a TCP/TLS or WSS fallback — VNT does
  exactly this.

---

## 4. Platform integration reference

### 4.1 Linux

- **Device:** `/dev/net/tun`; `ioctl(TUNSETIFF)` with `IFF_TUN | IFF_NO_PI`
  (L3) or `IFF_TAP | IFF_NO_PI` (L2). `TUNSETPERSIST` keeps it after close;
  `TUNSETOWNER` allows non-root opens.
- **I/O:** `read()`/`write()` whole IP packets (L3) or Ethernet frames (L2).
  Set `O_NONBLOCK` for event-loop integration; use `poll`/`epoll`.
- **Privileges:** root or `CAP_NET_ADMIN`. `CAP_NET_RAW` for `AF_PACKET`.
- **Routing:** rtnetlink (`RTM_NEWROUTE`), or `ip route`; policy routing with
  `fwmark` + `ip rule` is the standard way to avoid tunnel loops.
- **NAT:** nftables/iptables `MASQUERADE`; `TPROXY` for transparent proxying;
  eBPF/TC for high-performance forwarding.
- **DNS:** `/etc/resolv.conf`, `systemd-resolved` D-Bus, or `resolvconf`.
- **L2:** `AF_PACKET` raw sockets, bridge via `ip link add br0 type bridge`.
- **Multi-queue:** `IFF_MULTI_QUEUE` + one fd per queue thread.
- **Offloads:** TUNSETOFFLOAD, GSO/GRO, `sendmmsg`/`recvmmsg`, `io_uring`.

### 4.2 Android

- Host app extends `android.net.VpnService`; native code receives a file
  descriptor, never creates a TUN itself.
- `VpnService.Builder`: `addAddress`, `addRoute`, `addDnsServer`,
  `addSearchDomain`, `setMtu`, `setBlocking`, `setSession`, `allowFamily`
  (`AF_INET`/`AF_INET6`), `addAllowedApplication`/`addDisallowedApplication`,
  `excludeRoute`, `setConfigureIntent`.
- `establish()` returns `ParcelFileDescriptor`; `detachFd()` hands raw fd to
  native. `protect(socket)` exempts a socket from the VPN to avoid loops.
- Only **one** VPN can be active; `onRevoke()` must be handled.
- `addAddress` does not add a route — add the virtual subnet route explicitly.
- Full tunnel = `addRoute("0.0.0.0", 0)` (plus IPv6 `::/0`); split tunnel =
  specific routes or `addDisallowedApplication`.
- Foreground service + notification required for long-running VPN; Android 14+
  declares `foregroundServiceType="specialUse"` or `vpn`? (Use `specialUse` for
  non-system VPN apps; `VpnService` itself is the sanctioned mechanism.)
- Per-app VPN via `addAllowedApplication`; always-on VPN via system settings;
  `setBlocking(true)` for a blocking TUN fd (flow control; the kill switch is
  the system "Always-on VPN + Block connections without VPN" setting).
- MTU: 1380 typical; `setMtu` must be ≤ underlying MTU − overhead.
- JNI: `System.loadLibrary`, `@Keep` native methods, `jobject`/`jbyteArray`
  marshalling; callbacks must attach the thread (`AttachCurrentThread`).
- Battery: batch wakeups, avoid per-packet JNI, keep native loop in one thread,
  use `FileDescriptor` readiness rather than polling.
- Doze/App Standby: use foreground service; handle network changes via
  `ConnectivityManager.NetworkCallback`.

### 4.3 macOS

Two deployment models:

1. **CLI/daemon with `utun` (root).**
   - `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, `ioctl(CTLIOCGINFO)`
     with `com.apple.net.utun_control`, connect `sockaddr_ctl`, `getsockopt(UTUN_OPT_IFNAME)`.
   - Every packet has a **4-byte address-family header** (`AF_INET`/`AF_INET6`).
   - Routes via routing socket (`PF_ROUTE`) or `route(8)`; DNS via `scutil`.
   - Requires root → use a small SUID helper or a launchd daemon.
2. **App / App Store with NetworkExtension.**
   - `NEPacketTunnelProvider` (+ `NETunnelProviderManager`) runs in an app
     extension or system extension.
   - Entitlements: `com.apple.developer.networking.networkextension`
     (`packet-tunnel-provider`), app sandbox, notarization for distribution.
   - `NEPacketTunnelNetworkSettings`: `IPv4Settings`, `IPv6Settings`,
     `DNSSettings`, `MTU`, `includedRoutes`/`excludedRoutes`.
   - System extension approval UX on macOS 10.15+.
   - No raw `utun` from a sandboxed app.

For vNAT: ship the CLI/daemon path first (Linux parity), then the
NetworkExtension wrapper for the GUI/App Store build.

### 4.4 Windows

- **Wintun** is the recommended L3 TUN (used by WireGuard).
  - `wintun.dll` side-by-side; resolve functions at runtime
    (`LoadLibraryEx` + `GetProcAddress`), never link the import lib.
  - `WintunCreateAdapter(name, tunnel_type, requested_guid)` →
    `WintunStartSession(adapter, ring_capacity)` (ring 128 KiB–64 MiB, power
    of two) → `WintunReceivePacket` / `WintunReleaseReceivePacket` /
    `WintunAllocateSendPacket` / `WintunSendPacket`.
  - `WintunGetReadWaitEvent` for blocking waits; `WintunGetAdapterLUID` for
    routing.
  - Requires Administrator to create the adapter.
- **TAP-Windows6** (`tap0901`) only if true L2 is needed; heavier install.
- **Routing:** `CreateIpForwardEntry2` / `GetBestRoute2`; `netsh interface ipv4
  add route`; route metrics matter for split tunnel.
- **DNS:** `SetInterfaceDnsSettings` (Win10+) or NRPT
  (`DnsSetPolicyTable` / PowerShell `Add-DnsClientNrptRule`).
- **NAT:** kernel NAT via `New-NetNat` (Win10+) or WFP callout; userspace NAT
  only for overlay-internal traffic.
- **Service:** Windows Service (`ServiceMain`) for background; UI via a
  separate tray app; named-pipe IPC.
- **Firewall:** prompt on first bind; add rules for the relay ports if needed.
- **Loop avoidance:** route the relay/control endpoints via the physical
  gateway (`CreateIpForwardEntry2` with lower metric), or bind sockets to the
  physical interface.

### 4.5 iOS (later, same as Android conceptually)

- `NEPacketTunnelProvider` mandatory; no raw utun.
- Entitlement `packet-tunnel-provider`; provisioning profile.
- `setTunnelNetworkSettings` with routes/DNS/MTU.
- `NEPacketTunnelFlow.readPackets`/`writePackets` (arrays of `Data`).
- Background limits: the extension is killed aggressively; reconnect fast.

---

## 5. Zig 0.16 / 0.17 — what changes how we build

### 5.1 Zig 0.16.0 (released 2026-04-13)

**I/O as an Interface — the headline change.** All I/O takes an `Io` instance.

- `Io.Threaded` — thread-backed, feature-complete (what `main` uses by default).
- `Io.Evented` — M:N green threads, experimental; **no networking yet**.
- `Io.Uring` — Linux io_uring proof-of-concept; no networking yet.
- `Io.Kqueue`, `Io.Dispatch` — proofs-of-concept.
- `Io.failing` — test double.
- Primitives: `Future`, `Group`, `Select`, `Batch`, `Queue(T)`, `Clock`,
  `Duration`, `Timestamp`, `Timeout`.
- `io.async` (may run inline) vs `io.concurrent` (must run concurrently,
  can fail with `error.ConcurrencyUnavailable`). Futures have `await`/`cancel`;
  cancelation returns `error.Canceled`.
- `std.Io.net` is async: DNS queries race, TCP connects race, first success
  cancels the rest. Works even with `-fsingle-threaded`.
- **No ws2_32.dll on Windows** — networking goes through NtDll.
- `std.process.Init` ("Juicy Main"): `main(init: std.process.Init)` gives
  `gpa`, `io`, `arena`, `environ_map`, `preopens`, args.
- `std.posix` / `std.os.windows` medium-level functions removed → go higher
  (`std.Io`) or lower (`std.posix.system`).
- `@cImport` deprecated → `b.addTranslateC` in `build.zig` (or the translate-c
  package).
- `@Type` removed → `@Int`, `@Struct`, `@Union`, `@Pointer`, `@Fn`, `@Tuple`,
  `@EnumLiteral`.
- Pointers forbidden in packed structs/unions; no unused bits in packed unions.
- Unmanaged containers are the norm; `Thread.Pool` removed.
- New `std.compress.deflate`; AES-SIV, AES-GCM-SIV, Ascon added.
- Min OS: Linux 5.10, macOS 13.0, Windows 10.
- Build: local package override, project-local fetch, test timeouts,
  `--error-style`, `--multiline-errors`.

**Implications for vNAT:**
- Design every module to take `io: std.Io` (store it on context structs).
- Prefer `std.Io.net` for UDP/TCP; it is the only path that is portable and
  future-proof across backends.
- Since `Io.Evented` lacks networking, a high-performance data plane may need
  a custom epoll/kqueue/IOCP loop *below* `Io`, or use `Io.Threaded` with
  worker threads and blocking sockets (SoftEther-style). Decide early.
- Keep FFI exports free of `Io` (pass C ABI handles and callbacks).

### 5.2 Zig 0.17.0 (released 2026-10-01)

- "Language Stability Progress" — fewer breaking changes going forward.
- `@bitCast` semantics tightened (result type required in more places).
- `@backingInt` / `@fromBackingInt`, `@divCeil`.
- `void{}` syntax removed; `errdefer` capture removed; `i0` removed.
- `@hasDecl` returns true only for public declarations.
- `fmt.allocPrint` moved to `mem.Allocator`; printing enhancements.
- `std.zon.parse` reworked.
- `bit_set` variants renamed; managed variant deprecated.
- `lang.OptimizeMode` → `lang.Optimize`; `lang.Optimize.runtimeSafety`.
- `@import("builtin")` deprecations.
- Build system: **configure cache poisoning** concept, cache rework, separate
  maker/configurer processes, `findProgram`/`findProgramLazy`, build server
  protocol.
- Toolchain: LLVM 22, glibc 2.44, Linux 7.2 headers, macOS 27 headers,
  `zig objdump`, resinator updates.

**Recommendation:** target **0.16.x for the first release** to match the
SoftEther stack and existing CI, but keep the code free of 0.16-only idioms so
the 0.17 bump is a mechanical change. Add a CI job that builds both.

### 5.3 Zig crypto available in std (no OpenSSL needed for the data plane)

- `std.crypto.aead.chacha_poly` (ChaCha20-Poly1305) — preferred (fast in
  software on ARM/x86 without AES-NI).
- `std.crypto.aead.aes_gcm` — preferred when AES-NI/ARMv8 crypto is present.
- `std.crypto.aead.aes_gcm_siv`, `aes_siv`.
- `std.crypto.dh.X25519`, `std.crypto.sign.Ed25519`.
- `std.crypto.kdf.hkdf` (HKDF-SHA256), `blake3`, `sha2`, `hmac`.
- `std.crypto.random` for CSPRNG.
- **No std TLS server.** `std.crypto.tls.Client` is client-only. For server
  TLS: OpenSSL (SoftEther approach), `zigtls`, or avoid TLS entirely with a
  Noise/WireGuard-style handshake.

### 5.4 Ecosystem libraries to evaluate (not dependencies yet)

| Need | Candidate | Notes |
|---|---|---|
| QUIC | `zquic` (zigstack), `quic` (devnw), `quic-zig`, `colibri` | Pure Zig, 0.16.x; maturity varies — spike before committing |
| TLS 1.3 (server) | `zigtls`, `tls` (devnw) | Needed only if we choose TLS control plane |
| libp2p | `blockblaz/zig-libp2p` | WIP; QUIC + gossipsub; useful reference for relay/hole-punch protocols |
| TUN | hand-rolled (SoftEther code) | Keep; no mature cross-platform Zig TUN crate |
| Serialization | `std.zon`, hand-rolled binary | Avoid pull deps; wire format should be versioned and explicit |
| HTTP/3 | `colibri` | Only if the control plane needs it |

---

## 6. Wire protocol design notes

### 6.1 Layering

```
┌──────────────────────────────────────────────────────────┐
│ app / CLI / GUI                                          │
├──────────────────────────────────────────────────────────┤
│ vNAT API (Zig) + C ABI (FFI for Android/iOS/desktop)     │
├──────────────────────────────────────────────────────────┤
│ session: virtual IP, routes, DNS, policies               │
├──────────────────────────────────────────────────────────┤
│ overlay: peer table, path selection, relay, keepalive    │
├──────────────────────────────────────────────────────────┤
│ transport: UDP (+QUIC/TCP/WSS fallback), AEAD, FEC, ARQ  │
├──────────────────────────────────────────────────────────┤
│ control: identity, auth, IPAM, signaling, config push    │
├──────────────────────────────────────────────────────────┤
│ datapath: TUN/TAP fd, packet codec, NAT/gateway          │
└──────────────────────────────────────────────────────────┘
```

### 6.2 Packet format sketch

Fixed header (little-endian), then AEAD-protected payload:

```
version:u8 | type:u8 | flags:u16 | session_id:u32 | seq:u64 | ack:u64
| key_id:u32 | nonce:u96 (or derived) | payload_len:u16 | ciphertext | tag:u128
```

Rules:
- AEAD associated data covers the header (everything except ciphertext/tag).
- Replay window (e.g. 1024 packets) per session/key.
- Handshake: Noise IK (`X25519 + ChaCha20-Poly1305 + SHA-256/HKDF`) with a
  network PSK mixed in; rekey every N packets / T seconds.
- Control messages are a separate type, always encrypted, length-prefixed.
- Version negotiation in the first message; unknown versions get a typed error.

### 6.3 Path selection

```
for each peer:
  candidates = [direct_v6, direct_v4, lan, relay]
  race candidates (staggered by RTT hints)
  first validated path wins; keep others as warm standbys
  on loss/latency regression → re-race
  relay path always available
```

Validation: authenticated ping/pong with nonce + RTT/loss EWMA.

### 6.4 Addressing / IPAM

- Virtual IPv4: per-network `/24` (or larger) pool allocated by control plane;
  sticky by `device_id`.
- Virtual IPv6: ULA `fdXX:...::/96` derived from virtual IPv4 (VNT pattern) or
  a separate pool.
- Avoid collisions with the host's real LAN: allow a configurable base CIDR and
  detect conflicts (VNT's #1 support issue).
- Subnet routes: advertise physical LANs (`10.0.0.0/8` etc.) as overlay routes
  with next-hop = node.

---

## 7. Security model

### 7.1 Threat model

| Adversary | Capability | Mitigation |
|---|---|---|
| Network observer | Passive traffic analysis | AEAD, padding, optional cover traffic |
| Malicious relay | Sees ciphertext + metadata | E2E keys never at relay; metadata minimization |
| Compromised control plane | Can reorder/deny, hand out IPs | Keys pinned/TOFU; signed config; no plaintext keys |
| Malicious peer | Authenticated but hostile | Per-network membership, ACLs, rate limits |
| Local unprivileged user | Can read process memory? | Key storage in OS keystore; memory locking |
| Rootkit / root | Full control | Out of scope |

### 7.2 Key management

- Device identity: Ed25519 keypair; public key = device ID.
- Network membership: network ID + PSK (password/token) or control-plane
  issued certificate.
- Session keys: X25519 ECDH + HKDF with separate labels for each direction and
  purpose (encrypt / MAC / IV).
- **Do not** derive MAC keys by hashing encryption keys (SoftEther RCA bug).
- Nonce discipline: 64-bit counter + random session salt; never reuse.
- Rekey: after 2^48 packets or 1 hour, whichever first; overlap old key for a
  short grace period.
- Post-quantum option later: hybrid X25519 + ML-KEM (std has `ml_kem`).

### 7.3 Authorization

- Per-network ACLs: which peers/subnets can reach which.
- Per-device tags/roles (e.g. `gateway`, `exit-node`, `client`).
- Control-plane tokens scoped to a network; rotate on revoke.
- Rate limiting and connection limits per peer to resist abuse.

---

## 8. Performance engineering

- **Batch syscalls:** `recvmmsg`/`sendmmsg` (Linux), `recvmsg_x`/`WSASendMsg`.
- **Multi-queue TUN:** `IFF_MULTI_QUEUE` + one worker per queue.
- **io_uring** for Linux (once `Io.Uring` matures, or hand-rolled now).
- **GSO/GRO + UDP_SEGMENT** offloads; TUNSETOFFLOAD.
- **FEC** for lossy paths (adaptive parity), but avoid adding latency.
- **Congestion control:** start with a simple BBR-like pacer for the overlay;
  don't reimplement TCP.
- **Path MTU:** clamp MSS (`--clamp-mss-to-pmtu` equivalent), default MTU
  1380 on mobile, 1420 on desktop, 1500 on LAN.
- **Allocation:** per-core buffer pools; zero-copy where the API allows;
  no allocation in the hot path.
- **Threading:** pin workers, `SO_REUSEPORT` for multi-flow distribution,
  lock-free rings between datapath and crypto workers.
- **Measurement:** `iperf3`, `tc netem`, `perf`, eBPF, packet capture at
  TUN and wire simultaneously.

---

## 9. Testing strategy

| Layer | Technique |
|---|---|
| Codec / crypto | Unit tests with known-answer vectors (RFC 8439 for ChaCha20-Poly1305, RFC 7748 for X25519) |
| Protocol state machine | In-memory `ScriptedTransport` (SoftEther pattern) — deterministic, no sockets |
| Fuzzing | `zig build fuzz`, `std.testing.fuzz`, AST smith; fuzz decoders, handshake, config |
| Interop | Reference peer in Rust/Go or a second Zig build; WireGuard interop later |
| Platform | Linux netns + veth; Android emulator + device; macOS/Windows VMs in CI |
| Network conditions | `tc netem` (loss/reorder/duplicate/delay), NAT emulation |
| NAT matrix | Scripts to emulate EIM/EDM, CGNAT, double NAT, hairpin, UDP-block |
| Long-run | 24h soak with churn, rekey, network switches |
| Security | Replay/reorder tests, key-compromise simulation, fuzz control plane |

CI matrix:
- Linux x86_64/aarch64 (build + unit + netns integration)
- Android aarch64/armv7 (build + emulator smoke)
- macOS aarch64/x86_64 (build + utun unit)
- Windows x86_64 (build + Wintun smoke)

---

## 10. Operational / product requirements

- **Zero-config join:** one token/QR → device on the network.
- **Stable identity:** `device_id` persists; IP is sticky.
- **Self-hosted control plane + relay;** public service optional.
- **Headless daemon** + CLI + native GUI + Android app.
- **Observability:** `vnat status`, Prometheus metrics, structured logs,
  per-peer RTT/loss/path, traffic accounting.
- **Updates:** signed binaries, in-app update or package managers
  (Homebrew/winget/apt/Play Store).
- **Compliance:** no plaintext telemetry; document metadata exposure.
- **Licensing:** Apache-2.0 for our code (matches SoftEther); Wintun DLL
  redistributed under its permissive prebuilt license; zlib bundled.

---

## 11. Open questions to resolve before coding

1. **Product scope:** overlay-only (virtual LAN) or also internet egress
   (exit node / full tunnel)? This decides whether we need a userspace
   TCP/IP stack.
2. **NAT strategy:** packet-level OS NAT (fast, needs privilege) vs
   socket-per-flow userspace NAT (portable, slower) vs full userspace stack
   (portable, heavy). Pick per platform.
3. **Transport:** pure custom UDP + AEAD, or QUIC for everything? QUIC gives
   streams/multiplexing but adds complexity and NAT traversal still needs raw
   UDP probes.
4. **Control plane:** self-hosted only, or also hosted SaaS? Determines auth,
   billing, multi-tenancy.
5. **Android distribution:** Play Store (VpnService policy) vs F-Droid/APK.
6. **Windows driver policy:** Wintun (GPLv2 driver, permissive DLL) is fine to
   redistribute, but sign the installer; no custom kernel driver.
7. **macOS distribution:** Developer ID + notarization for CLI/daemon;
   NetworkExtension + App Store later.
8. **Zig version:** pin 0.16.x now, gate 0.17 with a CI job.

---

## 12. Reference implementations to mine

| Project | Language | What to take |
|---|---|---|
| `devstroop/SE` (SoftEtherVPN Zig) | Zig 0.16 | Adapter code, routing, NAT engine, FFI patterns, CI |
| `vnt-dev/vnt` | Rust | Product model, NAT punch scheduling, Android JNI flow, runtime config |
| `rustp2p-core` | Rust | NAT type detection + punch scheduler design |
| Tailscale (`tsnet`, `derp`) | Go | Control plane, DERP relay, path selection, NAT traversal write-up |
| WireGuard (`wireguard-go`, `wintun`) | Go/C | Noise handshake, Wintun integration, roaming |
| `netbird`, `zerotier`, `n2n`, `easytier` | Go/C++/Rust | Mesh routing, relay, NAT traversal variants |
| `floo` (YUX) | Zig | Token-authenticated tunneling in Zig, config style |
| `blockblaz/zig-libp2p` | Zig | Circuit Relay v2 + DCUtR in Zig (reference) |
| `zquic` / `quic-zig` | Zig | QUIC building blocks if chosen |
