# ADR-001 — Router-first product scope

- **Status:** Accepted
- **Date:** 2026-10-22
- **Deciders:** project owner

## Context

The earlier planning round framed vNAT as a P2P overlay VPN (virtual IPs,
NAT traversal, relay), following SoftEtherVPN and VNT. The new direction is a
**portable virtual router**: a device — Linux or Android — that attaches to
L2/L3 interfaces, bridges/routes between them, and provides NAT, DHCP, DNS and
firewall. The router must work for traffic originating from the device itself
*and* from devices connected over hotspot, USB tethering, or USB-C Ethernet.

These are related but different products:

| | Overlay VPN | Virtual router |
|---|---|---|
| Primary value | Reach peers across the internet | Turn a device into a router |
| Key modules | NAT traversal, relay, peer table | L2/L3 forwarding, NAT, DHCP/DNS |
| Android | Easy (VpnService) | Hard (tethering interception, root) |

## Decision

Build the **virtual router first**. The overlay/P2P transport becomes a future
*uplink port* (ADR-004), not the core.

v1 scope: Linux full router; Android VPN-mode router (no root) and root router
mode for tethering. No GUI.

## Consequences

- The core is a forwarding engine, not a peer-to-peer stack.
- NAT here means classic SNAT/DNAT/conntrack, not NAT traversal.
- The Android plan must confront tethering interception honestly.
- Some prior research (STUN/TURN/ICE, relay) is deferred but kept in
  `docs/RESEARCH.md` for the uplink module.

## Alternatives considered

1. **Overlay-first** — simpler Android story, but does not satisfy "Android as
   a router for tethered devices".
2. **Wrapper around nftables/iptables** — fast to build, not portable, and
   fails on Android/no-root.
3. **Both at once** — too much scope for v1.
