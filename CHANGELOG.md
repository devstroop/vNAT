# Changelog

All notable changes to vNAT are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- R0 scaffold: `build.zig`/`build.zig.zon`, cross-compilation for Linux and
  Android, CI matrix.
- Strict JSON configuration schema, parser and semantic validator.
- `vnat` CLI with `version`, `validate` and `help`.
- `std.Io` context helper and leveled text/JSON logger (stack-buffered).
- `Port` vtable, in-memory reference port, fixed-size buffer pool.
- Golden Ethernet/IPv4/UDP frame fixtures and round-trip tests.
- ADR-001…006 (router-first, hybrid datapath, Android tiers, overlay deferred,
  conntrack/NAT, config/journal).
- Userspace L2 bridge datapath: bridge membership, MAC learning/FDB aging,
  unicast/flood forwarding, per-bridge SVI addressing, bridge ARP resolution,
  and DHCP serving on any member port.

### Fixed

- Bound the ARP neighbour cache and miss-rate map; stale entries are pruned and
  the oldest entry is evicted at capacity (spoofed-ARP memory exhaustion).
- Synchronize the DNS cache between UDP/TCP workers, use separate upstream
  sockets per worker, and bound TCP query reads with a deadline.
- Age cached DNS record TTLs, apply RFC 2308 negative-cache TTLs from SOA
  records, return NODATA for non-A local-zone queries, and accept zone-only DNS
  configs.
- Reject DHCP pools that contain the router address and refuse to commit or
  decline that address defensively.
- Make journal address ownership host-exact rather than network-exact, and drop
  journal records when a link/address/route mutation fails.
- Make `examples/minimal.json` runnable with L2 ports and reject unsupported
  existing L3 ports, duplicate port devices, routes without a device,
  masquerade interfaces without an address, and DHCP pools containing the
  router address.
- Harden the DHCP client: random transaction IDs, reply/xid/server-id checks,
  NAK handling, T1/T2 renew and rebind timers, and explicit masquerade opt-in.
- Bring daemon-created TUN/TAP devices up before handing them to the datapath.
- Record the boot time in the persisted DHCP lease database and discard leases
  from a previous boot, so monotonic expiry timestamps cannot keep stale
  bindings alive after a reboot.
- Scope port forwards with the optional `in` ingress selector and match rules
  by ingress port.
- Cap supported MTUs at 1600 bytes (the 2048-byte frame buffer limit) and
  reject jumbo configuration with a typed validation error.
- Enforce firewall default input/forward policies (`drop`/`reject`/`accept`)
  in the datapath; allow-rule matching remains R6. Explicit port forwards are
  treated as administrator allows, and `default_out` rejects non-accept values
  until outbound policy is implemented. Reject bridge STP, VLAN-aware and
  kernel-offload options until implemented instead of silently ignoring them.
- Keep bridge floods running when one member is down or its MTU is exceeded,
  rate-limit bridge-wide ARP resolution, and send valid ARP probes for DHCP
  conflict detection.
- Retry DHCP client acquisition after repeated failures, accept ACKs/NAKs from
  a replacement server during RENEWING/REBINDING, and scope conflict detection
  to the local L2 segment.
- Fix negative DNS caching for NXDOMAIN responses that also carry a CNAME, and
  discard pre-`boot_ms` lease databases instead of restoring potentially stale
  leases.

### R2 — IPv4 forwarding (core)

- Ethernet II and IPv4 parsers/builders with strict length and checksum
  validation; single 802.1Q tag is parsed, tagged frames are dropped until R5.
- ARP request/reply generation, learning cache with freshness and port scoping,
  and rate-limited broadcast resolution requests.
- Longest-prefix-match FIB for connected and static routes.
- Forwarding pipeline: TTL decrement, IPv4/TCP/UDP checksum repair (ADR-007),
  ICMP unreachable/time-exceeded/frag-needed, egress MTU enforcement, Ethernet
  and TUN egress.
- `vnatd` data loop: polls ports, forwards frames and logs counters.
- Config interfaces/static routes populate local addresses, connected routes
  and the FIB.
- `scripts/test_route.sh`: two isolated hosts ping and fetch HTTP through
  `vnatd`; verifies TTL=63, TCP and graceful shutdown.
- Gratuitous ARP announcements for configured local addresses at daemon start.
- ARP pending-packet queue (32 slots, 1 s): the first packet to an unresolved
  neighbor is flushed on reply instead of being dropped.
- TUN/L3 ingress and egress: bare IPv4, local echo replies, ICMP errors and
  forwarding between TUN and L2 ports. `scripts/test_tun.sh` covers ICMP and
  TCP through a kernel TUN peer.
- `vnat iface set|del|up|down` and `vnat route add|del` with journal-before-
  mutation, ownership-gated deletes, and `vnat down` reverse rollback.
- JSONL journal under `$VNAT_RUN_DIR` (default `/run/vnat`), atomic and
  fsynced; failed applies remove their record; partial rollback keeps the
  journal for inspection and retry.
- `vnat journal` for inspecting recorded mutations.
- `scripts/test_journal.sh`: address/route/link mutations, duplicate no-ops,
  unmanaged-delete rejection, pre-existing state preservation and rollback.

### R4 — DHCP and DNS (in progress)

- DHCPv4 server in the forwarding path: pool allocation, MAC reservations,
  OFFER/ACK/NAK, DECLINE quarantine, RELEASE/INFORM, configurable lease time,
  domain, MTU, NTP and DNS options.
- Optional atomic lease database (`lease_db`): active bindings are restored
  on start, expired/conflicting records are ignored, and the file is rewritten
  every 60 s and on shutdown.
- UDP DNS forwarder with upstream retry, TTL cache, basic negative caching,
  configurable cache size (`dns.max_entries`) and counters.
- `scripts/test_dhcp.sh`: raw Ethernet DHCP client obtains a lease, pings the
  router and verifies persistence across a daemon restart.
- `scripts/test_dns.sh`: query through `vnatd`, answer from the fake upstream,
  then a cache hit; both tests run in CI.
- Not yet: DHCP ARP conflict probe, DNS DoH/DoT, and DHCP/DNS CLI verbs.
- Added: initial DHCP client on the uplink, DNS over TCP, split zones and a
  local `vnat.` / `router.vnat.` status zone.

### R3 — NAT and conntrack

- Userspace conntrack table: both-direction 5-tuple keys, TCP new/established/
  closing timeouts, UDP/ICMP/generic timeouts, 1 s GC, 65,536-entry cap and
  counters.
- SNAT/masquerade for TCP, UDP and ICMP echo: source address/port rewrite,
  source-port preservation, deterministic collision allocation, reverse
  translation and full IP/L4 checksum recompute.
- Forwarded TCP/UDP/ICMP-echo flows are tracked even without NAT; replies to a
  NAT address are reverse-translated before local delivery.
- DNAT/port forwarding for TCP/UDP with reverse translation; hairpin NAT SNATs
  back out the ingress port when the target is on the same segment.
- ICMP-error translation for tracked NAT flows: outer and quoted tuples are
  restored and quoted IP/L4 checksums are adjusted incrementally (RFC 1624).
- A translated-key conntrack index maps post-NAT packets back to their flow
  without colliding with original/reply keys.
- `scripts/nat_matrix.sh`: UDP source-port preservation and collision, ICMP
  echo, TCP HTTP through masquerade, WAN-to-internal DNAT, hairpin DNAT and
  SNAT/DNAT ICMP-error translation.
- Masquerade currently requires a static egress address (DHCP in R4); fragments
  and non-echo ICMP on SNAT egress are dropped and counted until translation
  lands. Full incremental checksum updates for ordinary rewrites are next.

### R1 — Linux ports

- AF_PACKET L2 ports with promiscuous membership and outgoing-frame filtering.
- TUN (`IFF_NO_PI`) and TAP ports, created from config (`"create": "tun"|"tap"`).
- rtnetlink link dump and link/addr/neigh monitor with bounds-checked parsing.
- Port manager with stable IDs, MTU application and hotplug refresh.
- `vnat port list`, `vnat status`, `vnat selftest`, and the `vnatd` daemon
  skeleton with graceful SIGINT/SIGTERM shutdown.
- `scripts/test_netns.sh`: veth L2 forwarding, TUN/TAP creation, netlink dump,
  manager status and daemon hotplug in a private netns.
