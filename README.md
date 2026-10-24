# vNAT

Headless virtual router implemented in Zig 0.16.x.

vNAT attaches network interfaces, forwards Ethernet and IPv4 traffic, and
provides NAT, DHCP, DNS, and journal-backed host configuration. It runs as a
daemon with a command-line interface and exposes a C ABI for embedded hosts.

## Capabilities

- AF_PACKET L2 ports and TUN/TAP L3 ports
- ARP handling, IPv4 forwarding, ICMP errors, and TTL processing
- Userspace connection tracking and garbage collection
- Source NAT, destination NAT, port forwarding, and hairpin handling
- DHCPv4 server and client with lease persistence
- DNS forwarding with cache, TCP fallback, and split zones
- Atomic, journaled route/address/link changes with rollback
- Cross-compilation for Linux and Android targets

## Requirements

- Zig 0.16.x
- Linux kernel with AF_PACKET support

## Build

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

Cross-build:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
zig build -Dtarget=aarch64-linux-android
zig build -Dtarget=arm-linux-androideabi
```

## Usage

Validate a configuration:

```sh
./zig-out/bin/vnat validate examples/minimal.json
```

Start the daemon:

```sh
./zig-out/bin/vnatd -c examples/minimal.json
```

Common commands:

```sh
vnat status [-c <config>]
vnat port list
vnat iface set <dev> <cidr> [-c <config>]
vnat route add <dst> [via <ip>] dev <dev> [-c <config>]
vnat down [-c <config>]
vnat journal [-c <config>]
vnat dhcp status [-c <config>]
vnat dns query <name> [-c <config>]
```

## Configuration

- `examples/minimal.json`: runnable example
- `examples/travel-router.json`: illustrative target-state configuration
- `examples/README.md`: example status notes

## Documentation

1. `docs/PRODUCT.md`
2. `docs/CORE-SCOPE.md`
3. `docs/ANDROID.md`
4. `docs/ARCHITECTURE.md`
5. `docs/PLAN.md`
6. `docs/RESEARCH.md`
7. `docs/SOURCES.md`
8. `docs/adr/`

Contributor rules: `AGENTS.md`.

## Implementation Status

- R0-R4: complete
- R5-R6: in progress (VLAN bridging and firewall core wired)
- R7: foundation in progress (C ABI, injected fd port, service lifecycle);
  JNI/VpnService host and proxy NAT pending
- R8-R9: planned

See `docs/PLAN.md` for milestone details.
