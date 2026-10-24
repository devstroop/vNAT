# vRouter — Product Definition

> Status: planning. Supersedes the overlay-first framing in the earlier draft.
> Companion docs: [CORE-SCOPE.md](./CORE-SCOPE.md),
> [ANDROID.md](./ANDROID.md), [ARCHITECTURE.md](./ARCHITECTURE.md),
> [PLAN.md](./PLAN.md).

## 1. One sentence

**vRouter turns a Linux machine or an Android device into an opt-in, portable
virtual router**: it attaches to L2/L3 interfaces, bridges or routes between
them, and provides NAT, DHCP, DNS, firewall and port forwarding — with no GUI
in v1, just a daemon and a CLI/API. An optional local web admin is post-v1.

## 2. Why this exists

Routers are normally fixed appliances. But the device in your pocket already
has Wi-Fi, cellular, USB-C Ethernet and USB tethering; a Linux mini-PC already
has multiple NICs. What is missing is a **portable, scriptable, auditable
routing engine** that can use those interfaces on demand, without flashing
OpenWrt, without a cloud account, and without a GUI in v1.

vRouter is that engine. It is *opt-in*: nothing changes on the host until the user
starts it, and everything it changes is journaled and rolled back.

## 3. Target user and use cases

| Persona | Scenario |
|---|---|
| Traveler | Phone on hotel Wi-Fi; laptop and tablet connect over hotspot/USB tethering; vRouter is the router doing DHCP/NAT/DNS/firewall |
| Field engineer | USB-C Ethernet on a phone/laptop; share link to a small LAN; capture traffic; port-forward a device |
| Homelab / dev | Linux box with 2–4 NICs; bridge a lab segment, route between VLANs, NAT to uplink |
| Privacy-conscious user | Android VPN-mode router that applies per-app routing/NAT/firewall on-device |
| Tester | Build arbitrary topologies in a container/netns with a declarative config |

## 4. Product shape

```
                 ┌──────────────────────────────────────────┐
   uplink ───────┤  vRouter core (userspace router)         │
   (eth/wlan/    │                                          │
    usb/wwan)    │  L2 bridge · L3 router · NAT · firewall  │──── LAN ports
                 │  DHCPv4 · DNS · conntrack · port forward │     (eth/usb/ap)
                 └──────────────────────────────────────────┘
                          ▲                    ▲
                    CLI / daemon         local API (unix socket)
                    config file          C ABI (Android host)
```

- **Core:** Zig library implementing the datapath and control plane.
- **`vrouterd`:** headless daemon, config-driven, journaled side effects.
- **`vrouter`:** CLI (also embeds the daemon for foreground use).
- **Android:** host app is thin — it supplies `VpnService` fd / root
  capabilities and renders status; all routing logic is in the core.
- **No GUI in v1.** JSON output + `vrouter status --watch` is the UI. An optional
  post-v1 local web admin consumes the same Unix-socket API; it is not part of
  v1 and never mutates host state directly (ADR-011).

## 5. Product principles

1. **Opt-in and reversible.** Every host mutation (route, address, bridge
   membership, NAT rule) is recorded and undone on stop/crash recovery.
2. **Portable core, native edges.** One forwarding engine; platform code only
   opens interfaces and configures the kernel.
3. **Userspace reference datapath, kernel fast path.** Correctness and
   portability first; opt-in offload where the OS can do it better.
4. **L2 and L3 are both first-class.** Bridge when the topology is L2; route
   when it is L3. Never force one model.
5. **Declarative config, imperative escape hatches.** Desired-state config plus
   CLI verbs for live changes.
6. **No GUI in v1, no cloud, no telemetry.** Local control only. The optional
   post-v1 web admin is an unprivileged local API client (ADR-011).
7. **Hostile input.** Every frame/packet/config byte is untrusted.

## 6. Capability tiers

| Tier | Platform | What vRouter can do |
|---|---|---|
| **T1 — Linux native** | Linux (root or `CAP_NET_ADMIN`+`CAP_NET_RAW`) | Everything: L2 AF_PACKET, TUN/TAP, netlink, bridge, NAT, DHCP, DNS, firewall, namespaces |
| **T2 — Android VPN** | Android, no root | On-device router: `VpnService` L3 port + protected uplink sockets; NAT/DNS/firewall for apps in the VPN profile |
| **T3 — Android router** | Android, root (Magisk/KernelSU) | Full portable router: L2/L3 ports on wlan/ap/usb/rmnet, bridge, intercept tethering, NAT, DHCP/DNS |
| **T4 — Desktop later** | macOS / Windows | L3 utun/Wintun ports, routes/NAT via OS APIs |

v1 ships **T1** and **T2**; **T3** is designed for and prototyped in the same
release if root testing hardware is available; **T4** is post-v1.

## 7. Non-goals (v1)

- GUI, mobile UI, web dashboard in v1 (local web admin is post-v1, ADR-011).
- Cloud control plane, accounts, billing, telemetry.
- P2P/VPN overlay, NAT traversal, relay (kept as a future uplink module; see
  `docs/RESEARCH.md` §3 and ADR-004).
- Dynamic routing protocols (OSPF, BGP, RIP).
- Full stateful L7 firewall / application identification.
- QoS/traffic shaping beyond basic rate limits.
- NAT64/464XLAT, ALGs (FTP/SIP), captive portal, 802.1X.
- Windows/macOS implementations.
- Play Store distribution of the root mode.

## 8. Success criteria for v1

1. Linux: two NICs + NAT + DHCP + DNS works on a bare box; `vrouter down` leaves
   the host exactly as it was.
2. Linux: L2 bridge between two NICs passes tagged and untagged traffic; STP
   optional.
3. Android (no root): apps under the VPN reach the internet through vRouter's NAT;
   per-app include/exclude works; survives network switch and reboot.
4. Android (root): a tethered laptop gets DHCP from vRouter and reaches the
   internet through vRouter's NAT, not the OS tethering NAT.
5. 24 h soak with interface flaps, no leaks, no stale rules.
6. Throughput: Linux ≥ 1 Gbps forwarded on loopback/veth; Android ≥ 150 Mbps
   in VPN mode, ≥ 300 Mbps in root mode (device-dependent).
7. Every mutation is visible in `vrouter journal` and reversible.

## 9. Naming and packaging

- Project: `vrouter`
- Binaries: `vrouter`, `vrouterd`
- Library: `libvrouter` / `libvrouter.a`
- Config: `/etc/vrouter/vrouter.json` (Linux), app-private dir (Android)
- State/journal: `/var/lib/vrouter/` (Linux)
- License: Apache-2.0
