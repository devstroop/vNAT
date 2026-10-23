# ADR-005 — Conntrack and NAT design

- **Status:** Accepted (R3 subset; DNAT/hairpin/ICMP errors follow)
- **Date:** 2026-10-22
- **Depends on:** ADR-002 (userspace reference datapath)

## Context

NAT, port forwarding, hairpin and the firewall all need connection state.
Linux offers nf_conntrack, but vNAT must work on unrooted Android (no netfilter)
and must be testable without privileges. Doing NAT correctly also means
handling ICMP query translation, fragments, TCP teardown and port exhaustion.

## Decision

Implement a single **userspace conntrack table** used by the reference
datapath and by kernel-offload bookkeeping.

### Key and canonical direction

- Key: `{proto, src_ip, src_port, dst_ip, dst_port, zone}`.
- The first packet creates an entry with `original` and `reply` tuples; the
  reply tuple swaps addresses/ports. A second lookup with the reply tuple
  matches the same entry.
- `zone` is the ingress interface index (prevents cross-zone collisions).

### Table

- Sharded by a hash of the key; default 64 shards, 65,536 entries total
  (borrowed from SoftEther's `MAX_NAT_ENTRIES`). Configurable later.
- Each shard owns its entries; no global lock on lookup. Control-plane
  snapshots are swapped, never mutated in place.
- Eviction: expired first, then oldest `ESTABLISHED` under memory pressure.
  Exhaustion increments `ct_dropped` and logs rate-limited at `warn`.

### Timeouts (defaults)

| State | Timeout |
|---|---|
| TCP SYN / SYN-ACK | 10 s |
| TCP ESTABLISHED | 300 s |
| TCP FIN / CLOSE_WAIT | 120 s |
| TCP TIME_WAIT | 30 s |
| UDP (any) | 30 s |
| ICMP query | 30 s |
| Other IP protocols | 60 s |

GC runs every second; a sweep is O(expired), not O(table).

### SNAT

- Allocate from `1024–65535` per `(proto, dst_ip)`; preserve the original
  source port when free.
- Deterministic fallback: hash of the original tuple, then linear probe.
- ICMP echo: rewrite the identifier and keep a reverse mapping.
- ICMP errors: rewrite the embedded original packet's tuple and checksum.
- Never rewrite the outer IP checksum incrementally without also updating the
  L4 checksum (see RFC 1624 for the incremental method).

### DNAT / port forwarding

- DNAT rewrites destination before routing; the reply is un-NATed by the
  conntrack entry.
- Hairpin (LAN client → public IP → same LAN host) is supported: the reply
  must be SNATed back to the router's LAN address.

### Fragments (IPv4)

- Track fragments by `{src, dst, id, proto}`.
- Only the first fragment carries L4 ports; subsequent fragments are matched
  to the same entry and forwarded without re-reading ports.
- Overlapping fragments are dropped (RFC 5722 policy).

### Checksums

- Recompute L3/L4 checksums on egress by default.
- Use incremental updates only when the offload backend is known to handle the
  affected layer; never trust NIC offload on Android.

### Interaction with the firewall

- The firewall consults conntrack first: `established,related` is accepted
  before rule evaluation.
- NAT decisions are recorded on the entry so both directions are symmetric.

## Implementation status (R3)

- One sharded-map placeholder is implemented as a single table with both
  directions mapped to the same entry and the ingress/egress port as the zone;
  sharding/epoch reclamation is deferred.
- GC is a 1 s full sweep; cap 65,536. Exhaustion drops new flows and counts.
- TCP state is flag-based (`new`, `established`, `closing`) with SYN 10 s,
  established 300 s, FIN 120 s and RST 10 s; the full FSM is pending.
- SNAT covers TCP, UDP and ICMP echo. Source ports are preserved when free and
  allocated by hash/probe otherwise. Mapping is per flow, not yet
  endpoint-independent.
- ICMP echo identifiers are translated; ICMP errors are not.
- Masquerade requires a static egress address until DHCP lands (R4).
- Fragments and non-echo ICMP on a SNAT egress are dropped and counted.
- Checksums are recomputed in full; incremental updates are pending.
- DNAT, port forwarding and hairpin are next.

## Consequences

- One source of truth for NAT/firewall state, identical on Linux and Android.
- Must be fuzzed and soak-tested; a bug here is a security bug.
- Kernel NAT offload must publish its state into the same accounting view or
  be marked `opaque` in `vnat status`.
- No ALGs in v1 (FTP/SIP/PPTP); document the limitation.

## Alternatives considered

1. **nf_conntrack only** — fails on unrooted Android and makes tests
   privileged.
2. **Per-flow user-space proxy** — too slow for UDP and breaks transparent
   forwarding semantics.
3. **eBPF conntrack** — post-v1; device support is uneven.
