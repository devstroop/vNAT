# vNAT

Portable virtual router in Zig 0.16.x: L2/L3 forwarding, bridging, IPv4 routing,
NAT, DHCP, DNS, and firewall for Linux and Android. No GUI. Daemon + CLI +
local API.

## Status

- R0–R3: complete (ports, forwarding, journal, conntrack, SNAT/DNAT, hairpin,
  ICMP-error translation).
- R4: in progress (DHCP server/client, DNS forwarder, lease persistence, CLI
  status/query; conflict probe done).
- R5–R9: planned (bridge, firewall, control plane, Android, performance).

See `docs/PLAN.md` for milestones and `docs/CORE-SCOPE.md` for the v1 contract.

## Build

Requires Zig 0.16.x.

```bash
zig build
zig build --release=fast
zig build test
```

## Tests

```bash
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

```bash
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
zig build -Dtarget=aarch64-linux-android
zig build -Dtarget=arm-linux-androideabi
```

## Configuration

```bash
./zig-out/bin/vnat validate examples/minimal.json
./zig-out/bin/vnat validate examples/travel-router.json
```

`examples/minimal.json` is runnable. `examples/travel-router.json` is
illustrative of target-state features. See `examples/README.md`.

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

Agent/contributor rules: `AGENTS.md`.

## License

Not specified.
