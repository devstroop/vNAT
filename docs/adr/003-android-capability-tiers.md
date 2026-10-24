# ADR-003 — Android capability tiers

- **Status:** Proposed (needs sign-off on root scope)
- **Date:** 2026-10-22

## Context

Android does not grant apps raw network access:

- No `AF_PACKET`, no TUN/TAP creation, no route/iptables changes without root.
- `VpnService` provides **one L3 TUN fd for the app's user profile only**.
- Traffic from hotspot / USB-tethered clients is handled by the OS tethering
  stack (netd/`tetherctrl`, BPF offload); `VpnService` does not see it.

Yet the product needs an Android device to act as a router, including for
tethered devices.

## Decision

Ship two explicit tiers, sharing one core:

### Tier A — VPN router (no root)
- `VpnService` fd as an L3 port; protected sockets as uplink.
- Proxy NAT (TCP/UDP/ICMP) inside vRouter; DNS/firewall/per-app policy.
- Shippable on Play Store. Cannot serve tethered clients.

### Tier B — Portable router (root)
- Raw ports (`AF_PACKET`) on `wlan0`/`ap0`/`usb0`/`rmnet*`; TUN/TAP; netlink.
- Userspace bridging/routing/NAT; optional kernel offload.
- Tethering takeover via **Strategy 1** (kernel forwarding + vRouter-owned
  NAT/firewall rules) with mandatory journal/rollback. **Strategy 2**
  (NFQUEUE interception) behind an experimental flag.
- Distributed outside Play Store; capability-probed (`su`, SELinux, netlink,
  iptables/nft).

Tier B is in v1 scope **if rooted test hardware is available**; otherwise it
slips to v1.1 without blocking Tier A.

## Consequences

- The Android app must present the tier honestly; no silent privilege
  escalation.
- Tier B needs a robust rollback (`vrouter doctor --repair`) because it mutates
  global tethering state.
- OEM/SELinux variance is the top support risk; capability probes and clear
  errors are mandatory.
- The core must not assume Linux-only APIs; Android-specific hosting lives in
  `port/android/` and `app/service.zig`.

## Alternatives considered

1. **Root-only Android** — simplest technically, unacceptable reach and Play
   Store risk.
2. **No-root only** — cannot satisfy the tethering-router requirement.
3. **Userspace AP creation** — not possible with public Android APIs.
4. **eBPF/XDP interception** — post-v1; kernel support too variable.
