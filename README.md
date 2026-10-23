# vNAT

Portable virtual router in Zig 0.16.x for Linux and Android.

## Quick Start

```sh
zig build
./zig-out/bin/vnat validate examples/minimal.json
./zig-out/bin/vnatd -c examples/minimal.json
```

## CLI

```sh
vnat version
vnat validate <config.json>
vnat status [-c <config>]
vnat port list
vnat iface set|del <dev> <cidr> [-c <config>]
vnat iface up|down <dev> [-c <config>]
vnat route add|del ...
vnat down [-c <config>]
vnat journal [-c <config>]
vnat dhcp status [-c <config>]
vnat dns query <name> [-c <config>]
```

## Build and Test

```sh
zig build
zig build test
bash scripts/test_netns.sh
bash scripts/test_route.sh
bash scripts/test_tun.sh
bash scripts/test_journal.sh
bash scripts/nat_matrix.sh
bash scripts/test_dhcp.sh
bash scripts/test_dns.sh
```

## Configuration

`examples/minimal.json` is runnable. `examples/travel-router.json` is illustrative.
See `examples/README.md`.

## Architecture

Userspace L2/L3 forwarding, conntrack, NAT, DHCP, DNS, journaled mutations.
See `docs/ARCHITECTURE.md`.

## Documentation

1. docs/PRODUCT.md
2. docs/CORE-SCOPE.md
3. docs/ANDROID.md
4. docs/ARCHITECTURE.md
5. docs/PLAN.md

## Status

R0-R3 complete. R4 in progress. R5-R9 planned.
