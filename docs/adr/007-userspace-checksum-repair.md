# ADR-007 — Repair transport checksums on forwarded IPv4

**Status:** Accepted (R2)
**Date:** 2026-10-23

## Context

vNAT reads frames from `AF_PACKET`. Locally generated packets can reach the
packet socket while the kernel still carries `CHECKSUM_PARTIAL`: the NIC (or
veth peer) is expected to finish the TCP/UDP checksum. vNAT copies the bytes,
rewrites the Ethernet header on another port and transmits them through a new
packet socket, so the offload metadata is lost and the peer receives an
invalid L4 checksum. ICMP is unaffected because the kernel computes its
checksum in software.

This was observed as successful ICMP but failed TCP through two veth pairs.

## Decision

For every forwarded, non-fragmented IPv4 packet, vNAT recomputes the TCP or
UDP checksum in software after decrementing TTL. The IPv4 header checksum is
always recomputed. UDP checksum `0` remains "no checksum" as allowed by
RFC 768; fragmented packets are forwarded as-is because their L4 checksum
covers the reassembled datagram.

## Consequences

- Forwarding is correct on veth, TAP and offload-enabled NICs without
  negotiating offload per port.
- One extra pass over the L4 payload per forwarded packet; revisited in the
  R3 performance work if offload negotiation makes it unnecessary.
- The checksum routine is shared with future NAT incremental updates.
- Fragmented traffic still depends on the sender's checksum; reassembly or
  offload-awareness is deferred.
