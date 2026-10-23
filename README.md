# vNAT

A portable, userspace virtual router written in Zig 0.16.x.

vNAT turns a Linux machine or Android device into an opt-in router: attach L2/L3
interfaces, bridge or route between them, and provide NAT, DHCP, DNS, firewall,
and port forwarding. The data plane is pure Zig; there is no GUI and no cloud
dependency.

## Features

- L2 ports via `AF_PACKET`; TUN/TAP L3 ports; netlink hotplug
- Ethernet and IPv4 forwarding with ARP, ICMP errors, TTL handling, MTU
  enforcement, and software checksum repair (ADR-007)
- Userspace conntrack with TCP/UDP/ICMP timeouts and garbage collection
- SNAT/masquerade, DNAT/port forwarding, hairpin NAT, ICMP-error translation
- DHCPv4 server and client, reservations, options, and persistent lease database
- DNS forwarder with UDP/TCP, caching, negative caching, split zones, and a
  local status zone
- Journaled host mutations with rollback (`vnat down`)
- CLI, daemon, and local API surface
- C ABI for Android/iOS/desktop hosts

## Platforms

- Linux: full feature set
- Android: VpnService (no root) and root router modes
- macOS/Windows: planned

## Build

Requires Zig 0.16.x.

```sh
zig build
zig build --release=fast
```

## Test

```sh
zig build test
bash scripts/test_netns.sh
bash scripts/test_route.sh
bash scripts/test_tun.sh
bash scripts/test_journal.sh
bash scripts/nat_matrix.sh
bash scripts/test_dhcp.sh
bash scripts/test_dns.sh
```

Cross-compilation:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
zig build -Dtarget=aarch64-linux-android
zig build -Dtarget=arm-linux-androideabi
```

## Configuration

```sh
./zig-out/bin/vnat validate examples/minimal.json
```

`examples/minimal.json` is runnable. `examples/travel-router.json` is an
illustrative target-state configuration. See `examples/README.md`.

## Documentation

Read in this order:

1. `docs/PRODUCT.md`
2. `docs/CORE-SCOPE.md`
3. `docs/ANDROID.md`
4. `docs/ARCHITECTURE.md`
5. `docs/PLAN.md`
6. `docs/RESEARCH.md`
7. `docs/SOURCES.md`
8. `docs/adr/`

Contributor and agent rules: `AGENTS.md`.

## Status

R0 through R3 are complete. R4 is in progress: DHCP server/client, DNS
forwarder, lease persistence, and basic CLI verbs are implemented; the DHCP
conflict probe and remaining CLI surface are in progress. R5 through R9 are
planned.

See `docs/PLAN.md` for milestones and `docs/CORE-SCOPE.md` for the v1 contract.
