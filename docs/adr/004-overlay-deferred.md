# ADR-004 — Overlay/P2P is a future uplink module

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Earlier planning invested in a P2P overlay: virtual IPs, STUN, hole punching,
relay, AEAD sessions (see `docs/RESEARCH.md` §2–§3). The router-first direction
does not require any of it: a router can uplink to the internet, another LAN,
or a tunnel. But an overlay is a compelling *uplink* for the router — e.g. an
Android travel router that reaches a home network without a public IP.

## Decision

Defer overlay/P2P to a post-v1 module. Model it as an **L3 port** (a virtual
interface) that the router can use like any other uplink:

```
router ──▶ overlay port (P2P/relay) ──▶ remote network
```

The `src/overlay/` tree is reserved. The transport, handshake, STUN/punch and
relay designs already researched are kept for that module.

## Consequences

- v1 has no NAT traversal, relay, or peer-to-peer code.
- The `Port` abstraction must be able to represent a tunnel interface from day
  one (it already does: L3 port).
- The router does not depend on a control plane or cloud service.
- Future overlay work can reuse the entire conntrack/NAT/firewall stack.

## Alternatives considered

1. **Overlay in v1** — doubles scope and delays the router.
2. **Never** — discards a strong differentiator; rejected.
