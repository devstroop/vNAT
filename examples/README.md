# Examples

| File | Status | Notes |
|---|---|---|
| `minimal.json` | runnable | Two L2 (AF_PACKET) ports, static LAN, DHCP pool. Covered by unit validation. |
| `travel-router.json` | illustrative | Shows bridge, DHCP, DNS, firewall, NAT, and port forwarding. Basic bridge forwarding and firewall default policies are wired; allow rules, STP, VLAN-aware bridging and kernel offload remain future work and are rejected when enabled. CI validates shape and semantics only. |
