# vNAT — Project Plan

> Router-first. Linux → Android. No GUI. Zig 0.16.x.
> Scope: [CORE-SCOPE.md](./CORE-SCOPE.md). Design: [ARCHITECTURE.md](./ARCHITECTURE.md).

## 1. Delivery strategy

Build the **portable core once**, prove it on Linux, then adapt Android in two
tiers. Every milestone ends with a runnable artifact and a test, not just code.

Vertical-slice order:

```
R0 skeleton ─▶ R1 ports ─▶ R2 IPv4 forwarding ─▶ R3 NAT/conntrack
   ─▶ R4 DHCP/DNS ─▶ R5 L2 bridge ─▶ R6 firewall
   ─▶ R7 Android VPN ─▶ R8 Android root ─▶ R9 IPv6 + hardening + v1.0
```

A usable Linux router exists at the end of **R4**. L2 bridging and Android
follow.

## 2. Milestones

### R0 — Foundations (1–2 weeks) — COMPLETE

- [x] Repo, license, `build.zig`, `build.zig.zon`, CI, `AGENTS.md`.
- [x] Pin Zig 0.16.0; add 0.17 build job (allowed to fail).
- [x] Cross-compile smoke: `x86_64-linux`, `aarch64-linux`,
      `aarch64-linux-android`, `arm-linux-androideabi`.
- [x] `std.Io` wiring (`io.zig`), leveled logging (`log.zig`), error taxonomy.
- [x] Config schema + strict parser + validation + `vnat validate`.
- [x] `Port` vtable + in-memory port + buffer pool + golden-frame harness.
- [x] ADR-001…006.

**Exit (met):** unit tests green; `vnat validate` accepts the example configs
and rejects unknown fields; all four targets compile.

### R1 — Ports and platform spine (2–3 weeks) — COMPLETE

- [x] `Port` vtable + `PortInfo` + buffer pools.
- [x] Linux `AF_PACKET` L2 port (simple recv/send; TPACKET_V3 deferred).
- [x] Linux TUN L3 port (`IFF_NO_PI`) + TAP L2 port.
- [x] rtnetlink: enumerate links, monitor link/addr/neigh events.
- [x] Port manager: stable IDs, hotplug refresh, MTU; admin up/down via the
      `Port` API.
- [x] `vnat port list`, `vnat status`, `vnat selftest`, `vnatd` skeleton.
- [x] netns smoke: veth L2 forwarding, TUN/TAP, status, daemon hotplug.

**Exit (met):** `scripts/test_netns.sh` moves frames across two veth pairs,
creates TUN/TAP devices, and observes a link event through `vnatd`.

### R2 — IPv4 forwarding (3–4 weeks)

- [x] Ethernet + IPv4 parsers/builders (bounds-checked; fuzz target in R9).
- [x] ARP cache, request/reply, learning, gratuitous ARP, and on-demand
      probing with a 32-packet pending queue; proxy ARP and periodic refresh
      are deferred.
- [x] RIB/FIB: connected + static routes, flat longest-prefix match (trie in
      R3 when route counts justify it).
- [x] Forwarding pipeline: TTL, IPv4/TCP/UDP checksums, ICMP
      unreachable/time-exceeded/frag-needed, egress MTU; non-DF fragmentation
      is deferred.
- [x] Interface addressing (`vnat iface set|del|up|down`) with journal.
- [x] Route management (`vnat route add|del`) with journal and ownership
      checks.
- [x] L3/TUN ingress and egress: bare IPv4, local echo/ICMP errors, forwarding
      to/from L2, pending-packet flush (`scripts/test_tun.sh`).
- [x] netns tests: host A ↔ router ↔ host B ping + TCP
      (`scripts/test_route.sh`), TUN peer ↔ router ↔ host B (`scripts/test_tun.sh`)
      and journal/rollback (`scripts/test_journal.sh`).

**Status: COMPLETE for the IPv4 path (L2 and TUN).** Deferred: proxy ARP,
periodic neighbor refresh, and fragmentation of non-DF packets (PMTUD via
ICMP frag-needed is implemented). None block the exit criterion.

**Exit (met):** Static IPv4 routing between two subnets works in netns;
`vnat down` restores journaled state.

### R3 — NAT and conntrack (3–4 weeks)

- [x] `conntrack`: 5-tuple table, TCP flag-based states, timeouts, GC, cap and
      counters (single shard; full FSM and sharding later).
- [x] SNAT/masquerade with source-port preservation, collision allocation and
      ICMP echo identifier translation.
- [x] DNAT/port forwarding + hairpin (TCP/UDP; ICMP port forwards rejected).
- [x] ICMP-error translation for tracked NAT flows (outer + quoted tuple,
      RFC 1624 quoted-L4 checksum adjustment).
- [ ] Incremental checksum updates for ordinary NAT rewrites (full recompute
      is correct but slower).
- [ ] `vnat nat …`, `vnat conntrack …` (needs the R7 control socket).
- [x] Exhaustion/limit behavior + counters.
- [x] netns matrix: SNAT TCP/UDP/ICMP, DNAT/hairpin and SNAT/DNAT ICMP-error
      translation are covered by `scripts/nat_matrix.sh`.

**Status: IN PROGRESS.** Conntrack, SNAT/masquerade, DNAT/port forwarding and
hairpin NAT are in the datapath (`src/nat/`, `src/l3/forward.zig`). Masquerade
requires a static egress address until R4 DHCP. Fragments and unrelated or
non-echo ICMP on SNAT egress are dropped (counted) rather than leaked; full
incremental checksum updates for ordinary rewrites remain.

**Exit:** LAN hosts reach an external network through vNAT's NAT; inbound port
forward works; conntrack survives 1 h churn.

### R4 — DHCP + DNS services (3–4 weeks)

- [x] DHCPv4 server: pool, MAC reservations, options, DECLINE, lease DB
      persistence and restore.
- [x] DHCP conflict probe (ARP before OFFER).
- [x] DHCP client on uplink (initial lease acquisition, connected route and
      masquerade installation).
- [x] DNS forwarder: UDP/TCP, TTL cache, negative cache, upstream pool.
- [x] DNS TCP listener/upstream fallback, split zones, local status zone.
- [x] `vnat dhcp status`, `vnat dns query` (offline, read lease DB / send query).
- [x] netns tests: `scripts/test_dhcp.sh` (lease, ping, persistence) and
      `scripts/test_dns.sh` (query + cache hit).

**Status: COMPLETE.** The DHCP server is integrated into the forwarding path
(no kernel socket), probes candidates before OFFER, uses option 61 client-id
as the lease identity when present, and persists leases when `lease_db` is
configured. DNS serves TCP, split zones and a local `vnat.` / `router.vnat.`
status zone. `vnatd` does not apply interface addresses, so DNS requires the
listen address to exist (use `vnat iface set` first).

**Exit:** `vnat` is a usable travel/home router on Linux: uplink DHCP, LAN
DHCP + DNS + NAT.

### R5 — L2 bridge (3–4 weeks)

- [x] FDB learning/aging/flooding; per-VLAN keys.
- [x] 802.1Q: PVID, trunk, access ports, VLAN filtering.
- [x] Broadcast/multicast handling.
- [x] Reassemble 802.1Q tags stripped by `PACKET_AUXDATA` VLAN offload.
- [x] Netns test with veth pairs and tagged traffic.
- [x] Storm control and loop protection (per-port flooded-frame limit).
- [ ] Optional STP 802.1D (port SoftEther `bridge/stp.zig`).
- [ ] Optional Linux kernel-bridge offload backend.
- [x] `vnat bridge list` inspection CLI (membership, PVID/tagged, SVI).

**Status: IN PROGRESS.** Userspace FDB learning/aging/flooding, broadcast and
multicast handling, per-VLAN FDB keys, PVID/tagged/access semantics, VLAN
filtering and offload tag recovery are implemented and covered by a veth
access/trunk netns test; `vnat bridge list` renders membership and SVIs.
Per-port storm control (broadcast/multicast/unknown-unicast) is enforced in the
bridge datapath. STP and kernel offload remain.

**Exit:** Two L2 segments bridged in userspace; tagged/untagged traffic passes;
kernel offload produces the same result.

### R6 — Firewall (2–3 weeks)

- [x] Rule parser/compiler: match fields, actions, conntrack states.
- [x] Default-deny inbound/forward; established/related shortcut.
- [x] Anti-spoofing (uRPF-lite, `firewall.rp_filter`).
- [x] ICMP/ARP/DHCP rate limits.
- [x] `vnat firewall test`; per-rule counters exported at runtime.
- [x] Tests: ordering, shadowing, state transitions.

**Status: COMPLETE.** Ordered first-match rules support `proto`, `src`,
`dst`, `sport`, `dport`, `iif`/`oif` (port, interface or bridge), actions
`accept`/`drop`/`reject` and `ct_state`; established traffic from conntrack is
accepted when no rule matches. `vnat firewall list` renders the compiled order;
`vnat firewall test` evaluates a synthetic packet; `vnat firewall counters`
reads the periodic counter snapshot written by `vnatd`. Strict uRPF-lite is
enforced when `firewall.rp_filter` is enabled and ICMP/ARP/DHCP rate limits
are configurable.

**Exit:** A default-deny router with explicit allows; no regressions in R2–R5
suites.

### R7 — Android VPN mode (3–4 weeks)

- [ ] JNI bridge + C ABI (`vnat_create`, `set_port_fd`, events).
- [ ] Proxy NAT backend (TCP/UDP/ICMP over protected sockets).
- [ ] Host `VpnService`: Builder, MTU 1380, routes, DNS, per-app split tunnel.
- [ ] Foreground service, `onRevoke`, always-on VPN + system lockdown support.
- [ ] Network-change handling + reconnect.
- [ ] Emulator tests; physical device smoke.

**Exit:** Apps under the VPN reach the internet through vNAT's NAT; split
tunnel works; survives Wi-Fi↔LTE.

### R8 — Android root router mode (3–4 weeks)

- [ ] Capability probe (`su`, AF_PACKET, netlink, iptables/nft, SELinux).
- [ ] Root helper start/stop; journal + rollback.
- [ ] Raw ports on `wlan0`/`ap0`/`usb0`/`rmnet*`; TUN/TAP.
- [ ] Tethering takeover (Strategy 1): forwarding + vNAT NAT/firewall rules,
      restore on exit.
- [ ] Experimental NFQUEUE interception (Strategy 2) behind a flag.
- [ ] Hotspot + USB tethering tests with a real client.
- [ ] `vnat doctor --repair` for crash recovery.

**Exit:** A tethered laptop gets DHCP from vNAT and reaches the internet
through vNAT's NAT; uninstall/stop restores tethering.

### R9 — IPv6, hardening, release (3–4 weeks)

- [ ] IPv6 forwarding + NDP; RA/DHCPv6 (v1.1 cut line if time-boxed).
- [ ] Fuzzing: all parsers 72 h clean.
- [ ] Crash/kill -9 recovery tests; journal replay.
- [ ] Performance: hit budgets in CORE-SCOPE §12.
- [ ] 7-day soak with flaps.
- [ ] Packaging: `.deb`/`.rpm`/AppImage, APK/AAB, systemd unit.
- [ ] Docs: quickstart, config reference, Android modes, troubleshooting.
- [ ] v1.0.0.

## 3. Effort summary

| Milestone | Weeks (solo) | Cumulative |
|---|---|---|
| R0 Foundations | 1–2 | 2 |
| R1 Ports/spine | 2–3 | 5 |
| R2 IPv4 forwarding | 3–4 | 9 |
| R3 NAT/conntrack | 3–4 | 13 |
| R4 DHCP/DNS | 3–4 | 17 |
| R5 L2 bridge | 3–4 | 21 |
| R6 Firewall | 2–3 | 24 |
| R7 Android VPN | 3–4 | 28 |
| R8 Android root | 3–4 | 32 |
| R9 Hardening/release | 3–4 | 36 |

≈8–9 months solo for a polished Linux+Android v1. A usable Linux router
(R0–R4) lands at ~4 months. Two people compress R1–R6 by ~35%.

## 4. First two weeks (completed as R0)

| Day | Task | Output |
|---|---|---|
| 1 | Repo, license, build.zig, AGENTS.md | Skeleton builds |
| 2 | CI matrix + cross-compile | Green CI |
| 3 | ADR-001…004 | Decisions locked |
| 4–5 | `io.zig`, logging, error taxonomy | Core plumbing |
| 6–7 | Config schema + strict parser + `vnat validate` | Config works |
| 8–9 | Port vtable + memory port + golden packets | Test harness |
| 10–12 | Linux TUN + AF_PACKET open/read/write | Ports work |
| 13–14 | netns echo test + `vnat port list` | R1 demo |

## 5. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Android root fragmentation (OEM/SELinux) | High | High | Mode A ships first; Mode B capability-probed; clear errors; no silent fallback |
| Android tethering takeover breaks on OEM | High | High | Kernel-rule strategy + journal/rollback + `doctor`; test on multiple OEMs |
| Userspace throughput too low | Medium | High | Kernel bridge/NAT offload; batching; AF_XDP post-v1 |
| Conntrack/NAT correctness (fragments, ICMP, hairpin) | Medium | High | Golden vectors + netns matrix + fuzz; conservative v1 scope |
| Zig 0.17 breakage | Medium | Medium | Pin 0.16; dual CI |
| Config/journal complexity | Medium | Medium | Strict schema, transactional apply, property tests |
| L2 bridge loops in the field | Medium | High | STP option, storm control, loop detection, docs |
| Privilege model on Linux | Low | Medium | Caps + systemd; optional privilege separation later |
| Scope creep (GUI/overlay) | High | Medium | Product non-goals; overlay deferred (ADR-004) |

## 6. Definition of done (v1)

- Linux: full router (L2 bridge, IPv4 routing, NAT, DHCP, DNS, firewall) with
  journal/rollback.
- Android Mode A: on-device router/NAT, split tunnel, always-on, network
  change resilience.
- Android Mode B: root router for tethered clients with safe rollback.
- 24 h soak, fuzzing clean, performance budgets met.
- CLI + API + docs + packages.
- No GUI, no cloud, no telemetry.

## 7. CI matrix

| Job | Target | Runs |
|---|---|---|
| linux-x86_64 | `x86_64-linux` | build, unit, netns, fuzz smoke |
| linux-aarch64 | `aarch64-linux` | build, unit |
| android-arm64 | `aarch64-linux-android` | build, emulator smoke (Mode A) |
| android-armv7 | `arm-linux-androideabi` | build |
| zig-next | all | build only (allowed to fail) |
| nightly-root | rooted device/emulator | Mode B smoke (manual gate) |

## 8. Decision log

| # | Decision | Status |
|---|---|---|
| 1 | Router-first (overlay deferred) | Accepted — ADR-001 |
| 2 | Userspace reference + kernel fast path | Accepted — ADR-002 |
| 3 | Android Mode A (no root) ships in v1; Mode B root in v1 if hardware allows | Proposed — ADR-003 |
| 4 | Overlay/P2P is a future uplink | Accepted — ADR-004 |
| 5 | Conntrack timeouts/port allocation | Accepted — ADR-005 (R3 subset) |
| 6 | Config/journal formats | Accepted — ADR-006 (R2 subset) |
| 7 | Repair transport checksums after AF_PACKET | Accepted — ADR-007 |
| 8 | Privilege model | Open — ADR-008 |
| 9 | Threading model | Open — ADR-009 |
