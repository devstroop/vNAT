# ADR-009 — Kernel bridge offload with a veth trunk

**Status:** Accepted (R5)
**Date:** 2026-10-24

## Context

`bridge.offload = "kernel"` was reserved but rejected. A kernel bridge gives
the best L2 forwarding rate on Linux, but vNAT still owns SVI addressing,
routing, NAT, DHCP, DNS and the firewall. Moving all of those into the kernel
would duplicate the portable userspace datapath and its tests.

The bridge also has to remain journaled: a failed setup or `vnat down` must
remove exactly the links, VLANs and master relationships vNAT created, without
adopting or disturbing pre-existing host state.

## Decision

For each bridge with `offload = "kernel"`:

- Create one Linux bridge and one veth pair. Enslave the bridge-side veth and
  every configured physical member to the kernel bridge.
- Open the peer veth as a single synthetic L2 port. Userspace bridging,
  routing, NAT, DHCP, DNS and firewall continue to run on that port as if it
  were the bridge's only member.
- Use one synthetic port per bridge. The synthetic port's config name is the
  bridge name, so SVI, firewall and NAT references keep using the same names.
- Enable kernel VLAN filtering when `vlan_aware` is set and clear the default
  PVID. Map each physical member's configured PVID untagged and its tagged
  VLANs tagged. Configure the veth trunk with PVID 1 untagged plus the union
  of member and SVI VLANs tagged.
- Let the kernel run STP when `bridge.stp` is set. The synthetic userspace
  bridge disables userspace STP so the two instances cannot disagree.
- Derive device names from a hash of instance and bridge name
  (`vnatbr<x>`, `vnatb<x>`, `vnatp<x>`), keeping every name within `IFNAMSIZ`
  without depending on config order.
- Reject setup when a target device already exists or a physical member is
  already enslaved. Setup is transactional from a journal checkpoint; failure
  replays the inverse back to that checkpoint.
- Reject a `pvid` that is also listed in `tagged` on an offloaded member: a
  kernel bridge VLAN entry cannot be both PVID-untagged and tagged. This is an
  explicit error rather than a silent semantic change.
- Reject `port.create` and `port.mtu` on offloaded members: the port manager
  does not open those devices, so it cannot apply the setting safely. Reject
  firewall `iif`/`oif` references to physical members; those frames enter
  through the synthetic trunk, never under the physical port's config name.
- Per-port `storm_control` is not enforced on offloaded members. vnatd warns
  while any member requests it; setting it to `0` acknowledges the limitation.
  Kernel bridge rate limiting is a future extension.

`vnat down` removes the veth pair, VLAN entries and bridge in reverse journal
order, then restores each physical member's previous link state. vNAT never
adopts an existing bridge or enslaved port.

## Consequences

- L2 switching runs in the kernel while L3/NAT/DHCP/firewall remain identical
  to the userspace path and its tests.
- Routed and SVI traffic crosses the veth trunk once in each direction; this
  is still faster for bridged traffic but adds overhead to routed flows.
- Kernel bridge state is visible through `bridge vlan show`, `bridge link` and
  `ip -d link`; vNAT counters cover only traffic that reaches userspace.
- A stale bridge from a crashed daemon makes startup fail with `Busy` until
  `vnat down` (journal) or explicit cleanup. That is preferred over adopting
  or resetting host state.
- Direct per-port references to offloaded physical members are no longer
  meaningful and are rejected by validation.
- Hotplug events for skipped physical members are consumed by the kernel;
  vNAT monitors only the synthetic trunk.

## Alternatives

- **Userspace only**: portable and fully observable, but leaves the available
  kernel L2 fast path unused.
- **Kernel bridge plus kernel NAT/firewall**: fastest, but duplicates policy in
  two implementations and breaks Android portability and the single journal.
- **Bridge one TAP port per physical member**: avoids VLAN translation, but
  requires one userspace port per member and defeats the offload.
