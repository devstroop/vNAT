# vNAT

A **portable virtual router** written in Zig. Turn a Linux machine or an
Android device into an opt-in router: attach L2/L3 interfaces, bridge or route
between them, and provide NAT, DHCP, DNS, firewall and port forwarding.

No GUI. No cloud. Daemon + CLI + local API.

**Platforms:** Linux (full) → Android (VpnService mode, and root router mode).
Zig 0.16.x. macOS/Windows later.

## What it does

```
                 ┌──────────────────────────────────────────┐
   uplink ───────┤  vNAT core (userspace router)            │
   (eth/wlan/    │                                          │
    usb/wwan)    │  L2 bridge · L3 router · NAT · firewall  │──── LAN ports
                 │  DHCPv4 · DNS · conntrack · port forward │     (eth/usb/ap)
                 └──────────────────────────────────────────┘
                          ▲                    ▲
                    CLI / daemon         local API (unix socket)
                    config file          C ABI (Android host)
```

- **Linux:** `AF_PACKET` L2 ports, TUN/TAP L3 ports, netlink hotplug, userspace
  bridge/routing/NAT, optional kernel offload. A tethered/hotspot device can be
  the upstream; LAN clients get DHCP/DNS/NAT.
- **Android (no root):** `VpnService` L3 port + protected uplink sockets;
  per-app split tunnel, DNS, NAT and firewall for on-device traffic.
- **Android (root):** raw interfaces, bridging, and tethering takeover so
  hotspot/USB clients route through vNAT.

## Build

Requires Zig 0.16.x (`zig version` must print `0.16.0`).

```bash
zig build
./zig-out/bin/vnat validate examples/travel-router.json
zig build test

# Linux netns smoke test: veth L2 forwarding, TUN/TAP, status, hotplug
bash scripts/test_netns.sh

# IPv4 routing: two isolated hosts ping and fetch HTTP through vnatd
bash scripts/test_route.sh

# TUN ingress/egress: kernel peer over TUN to a veth host (ICMP + TCP)
bash scripts/test_tun.sh

# Journal/rollback for vnat iface/route mutations
bash scripts/test_journal.sh

# NAT matrix: SNAT UDP/ICMP/TCP, DNAT/port forwarding and hairpin
bash scripts/nat_matrix.sh

# DHCP server: client lease + ping through the router
bash scripts/test_dhcp.sh

# DNS forwarder: query, answer and cache hit through vnatd
bash scripts/test_dns.sh
```

## Read in this order

| Doc | What it answers |
|---|---|
| [docs/PRODUCT.md](docs/PRODUCT.md) | Vision, personas, use cases, non-goals, success criteria |
| [docs/CORE-SCOPE.md](docs/CORE-SCOPE.md) | Exact v1 functional contract: ports, bridge, router, NAT, DHCP, DNS, firewall, CLI/API |
| [docs/ANDROID.md](docs/ANDROID.md) | What Android can and cannot do; VPN vs root modes; tethering interception |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout, interfaces, datapath backends, threading, security |
| [docs/PLAN.md](docs/PLAN.md) | R0–R9 milestones, effort, risks, CI |
| [docs/RESEARCH.md](docs/RESEARCH.md) | Knowledge base: SoftEtherVPN internals, NAT theory, Zig 0.16/0.17, platform APIs |
| [docs/SOURCES.md](docs/SOURCES.md) | Every reference URL |
| [docs/adr/](docs/adr/) | Accepted decisions |
| [AGENTS.md](AGENTS.md) | Rules for agents/contributors |

## Scope at a glance

**In v1:** Linux router (L2 bridge + IPv4 routing + NAT + DHCP + DNS +
firewall + port forwarding + journal/rollback); Android VPN mode; Android root
mode for tethered clients; CLI + daemon + Unix-socket API; C ABI.

**Out of v1:** GUI, cloud, overlay/P2P (ADR-004), dynamic routing, NAT64, ALGs,
QoS shaping, macOS/Windows.

## Installed skills

`.opencode/skills/` contains `skill-creator`, `doc-coauthoring`, and
`webapp-testing` from [anthropics/skills](https://github.com/anthropics/skills).

## Status

R2 is complete for the IPv4 path (L2 and TUN), including journaled
`vnat iface`/`vnat route` mutations and `vnat down` rollback. R3 is complete
for conntrack, SNAT/masquerade, DNAT/port forwarding with hairpin NAT, and
ICMP-error translation. R4 is in progress: the userspace DHCPv4 server
(reservations, options, DECLINE, optional lease DB) and a UDP DNS forwarder
with a TTL cache are integrated into `vnatd`; uplink DHCP, DNS TCP/split
zones and the DHCP/DNS CLI verbs are still open.
`scripts/test_route.sh`, `test_tun.sh`, `test_journal.sh`, `nat_matrix.sh`,
`test_dhcp.sh` and `test_dns.sh` cover forwarding, TUN, rollback, NAT,
DHCP and DNS. See [docs/PLAN.md](docs/PLAN.md).
