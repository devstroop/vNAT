# vNAT — Agent Guide

Portable virtual router in Zig 0.16+: L2/L3 forwarding, bridging, NAT, DHCP,
DNS and firewall for Linux and Android. No GUI in v1; an optional post-v1 web
admin is a separate unprivileged control-socket client (ADR-011). This file is
the contract for any agent working in this repo.

## Stack

| Layer | Location | Technology |
|---|---|---|
| Core library | `src/` | Zig, `std.Io`, `std.crypto` |
| Ports / datapath | `src/port/`, `src/l2/`, `src/l3/` | AF_PACKET, TUN/TAP, fd, netlink |
| NAT / firewall | `src/nat/`, `src/firewall/` | conntrack, SNAT/DNAT, rules |
| Services | `src/services/` | DHCPv4, DNS forwarder |
| CLI / daemon | `src/cli/`, `src/app/` | Zig |
| Executables | `exec/` | `vnat`, `vnatd`; `vnat-web` post-v1 |
| C ABI | `src/ffi.zig`, `include/vnat.h` | for Android/iOS/desktop hosts |
| Control plane | `src/control/` | config diff, journal, unix socket API |
| Web admin (post-v1) | `src/web/`, `exec/vnatweb/` | Zig HTTP, server-rendered HTMX, Unix-socket client |
| Tests | `test/` | unit, netns, fuzz, Android smoke |

## Commands

```bash
zig build                      # debug build
zig build --release=fast       # release
zig build test                 # unit tests
zig build test -Dtest-filter=ipv4
zig build shared-lib           # .so
zig build static-lib -Dtarget=aarch64-linux-android
bash scripts/test_netns.sh     # Linux L2/hotplug topology tests
bash scripts/test_route.sh     # IPv4 forwarding (ping + TCP)
bash scripts/test_tun.sh       # TUN ingress/egress (ICMP + TCP)
bash scripts/test_journal.sh   # iface/route journal + vnat down
bash scripts/nat_matrix.sh     # NAT/port-forward matrix (R3+)
bash scripts/test_firewall.sh  # ordered rules/default drop (R6)
bash scripts/test_vlan.sh      # 802.1Q access/trunk + SVI isolation (R5)
bash scripts/test_offload.sh   # kernel-bridge offload parity (R5)
bash scripts/perf.sh           # throughput smoke (R9)
```

Always run `zig build test`. For port/forwarding changes, also run
`scripts/test_netns.sh` and the relevant `scripts/test_route.sh` /
`scripts/test_tun.sh`.

## Non-negotiable rules

1. **Zig 0.16.x.** No removed syntax (`@Type`, `void{}`, `@cImport`). Use
   `b.addTranslateC` for C imports. See `docs/RESEARCH.md` §5.
2. **`std.Io` everywhere.** Any function that does I/O takes `io: std.Io`.
   Store it on context structs; never create a global.
3. **Pure-Zig data plane.** No OpenSSL on the packet path. `std.crypto` only.
4. **No allocation in the hot path.** Buffer pools; reuse; batch.
5. **Hostile input.** No `unreachable` on frames, packets or config. Use
   bounds-checked readers returning typed errors. Every parser is fuzzed.
6. **Journal before mutation.** Every host change (route, address, link,
   bridge membership, NAT rule) is recorded with its inverse. `vnat down` must
   restore the pre-start state.
7. **No silent fallback.** If a configured backend or capability is missing,
   fail with an actionable typed error.
8. **ABI stability.** `include/vnat.h` mirrors `src/ffi.zig`; changing an export
   updates the header, version and changelog.
9. **No secrets in logs.** Never log packet payloads, keys or tokens above
   debug level.
10. **One concern per PR.** Protocol/behavior changes need an ADR and tests.

## Code style

- `zig fmt` clean.
- Typed error sets per module (`PortError`, `NatError`, `DhcpError`, …); map to
  stable ABI codes at the FFI boundary.
- Types `PascalCase`, functions `camelCase`, constants `SCREAMING_SNAKE`.
- Modules expose `pub const X = struct { ... }` with `init`/`deinit`.
- Comments explain *why*, not *what*; reference RFC sections.
- No commented-out code; no dead flags.

## Architecture invariants

- The core never knows about Java/Swift/JNI types; hosts pass an fd or callback.
- Platform code lives only in `src/port/<platform>/` and `src/app/service.zig`.
- L2 and L3 are both first-class; a port declares which it carries.
- The data plane reads immutable snapshots (FIB, bridge table, ruleset) swapped
  by the control plane; no locks on lookup.
- A port belongs to at most one bridge or router zone.
- No packet is forwarded back out of its ingress port (bridge flood and
  hairpin NAT excepted).
- Forwarded IPv4 packets are re-checksummed in software; never trust offload
  metadata across ports (ADR-007).
- Default inbound/forward policy is drop.
- Overlay/P2P is a future uplink port (ADR-004), not part of v1.

## Danger zones

| Pitfall | Symptom | Fix |
|---|---|---|
| Stale routes/rules after crash | Blackholed or leaked traffic | Journal + `vnat doctor --repair` |
| AF_PACKET sees kernel-handled packets too | Double processing | Understand tap vs packet socket semantics; use AF_PACKET carefully |
| TUN/AF_PACKET checksum offload mismatch | Corrupt TCP checksums | Software repair on forward (ADR-007); offload only when negotiated |
| Android `addAddress` without `addRoute` | No traffic reaches TUN | Add the virtual-subnet route explicitly |
| Android `0.0.0.0/0` by accident | All internet hijacked | Only for full-tunnel mode |
| Android tethering takeover | Device loses hotspot after stop | Journal inverses; restore OS rules; test kill -9 |
| SELinux denial on Android root | `EPERM` despite `su` | Probe and report; ship `magiskpolicy` guidance |
| Android ABI mismatch | `SIGSEGV` on `System.loadLibrary` | Ship arm64-v8a/armeabi-v7a/x86_64; 16 KB page alignment |
| MTU ignored on bridge | Large packets dropped | Enforce egress MTU; MSS clamp |
| FDB/MAC flapping | Broadcast storms | Aging, storm control, optional STP |
| Conntrack exhaustion | New flows dropped | Cap + GC + metrics; document limits |
| IPv6 extension headers mishandled | Drops / bypass | Bounds-checked parser; explicit policy for unknown headers |
| Double NAT with host tethering | Asymmetric paths | Displace OS NAT or document coexistence |

## Testing expectations

- New parser: round-trip + malformed-input fuzz target.
- New forwarding behavior: golden packet vectors + the relevant netns scripts.
- NAT change: run `scripts/nat_matrix.sh` (SNAT, DNAT, hairpin, ICMP,
  fragments) and attach results.
- New host mutation: journal inverse + rollback test.
- Android change: emulator smoke (Mode A); rooted-device test (Mode B).
- Web admin change: handler/auth/CSRF tests + Playwright flows; the web process
  must never bypass the control socket.
- Performance-sensitive change: `scripts/perf.sh` before/after.

## Documentation expectations

- Behavior/protocol change → `docs/adr/NNN-*.md`.
- New config key → `docs/CORE-SCOPE.md` §9 + JSON schema.
- User-visible change → `CHANGELOG.md` under `Unreleased`.
- Platform quirk → `docs/ANDROID.md` or a platform note.

## Commits

- Conventional commits: `feat(scope): …`, `fix(scope): …`, `docs: …`,
  `test: …`, `refactor: …`, `chore: …`.
- Body explains *why*; reference the RFC/issue.
- Never commit secrets, keystores, or build artifacts.

## Branching

- `main` is release-ready.
- `develop` integrates completed work.
- Feature work uses `feat/*`, fixes `fix/*`, maintenance `chore/*`.
- Branches merge into `develop`, then `develop` into `main`.

## Skills available to agents

Installed in `.opencode/skills/`:
- `skill-creator` — build or improve repo-specific skills.
- `doc-coauthoring` — write ADRs, specs, proposals.
- `webapp-testing` — Playwright testing for the post-v1 web admin.

Use `skill-creator` to add a `vnat-networking` skill once the port/packet
interfaces stabilize.
