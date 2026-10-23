# ADR-002 — Userspace reference datapath with kernel fast path

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

A router can be implemented in two broad ways:

1. **Control-plane only:** configure the OS (forwarding sysctls, nftables NAT,
   kernel bridges, routes). Fast and simple on Linux; impossible on unrooted
   Android; not portable; opaque behavior.
2. **Userspace datapath:** open interfaces directly, parse/forward packets,
   implement bridging/NAT/conntrack in the process. Portable, observable,
   testable without root (except opening interfaces), but CPU-bound.

The product promises a *portable* virtual router with L2/L3 control and
Android support.

## Decision

Use a **userspace datapath as the reference implementation**, with **optional
kernel fast-path backends** selected by config:

- `userspace` (default): AF_PACKET/TUN ports, in-process bridge/router/NAT.
- `kernel_bridge` (Linux): create a kernel bridge for L2 offload.
- `kernel_nat` (Linux/Android root): program nftables/iptables for NAT.
- `nfqueue` (Android root, experimental): intercept tethered traffic into
  userspace.
- `proxy` (Android VPN mode): socket-per-flow NAT over protected sockets.

The core refuses to start if a requested backend is unavailable; it never
silently falls back.

## Consequences

- Correctness is defined by the userspace path; offloads must match its tests.
- We pay for buffer management, checksums, and conntrack ourselves.
- Linux performance requires batching/rings; >5 Gbps needs AF_XDP post-v1.
- Android root mode can still use kernel offloads for throughput.
- The same pipeline is testable in-memory without privileges.

## Alternatives considered

1. **Kernel-only control plane** — rejected: not portable, no Android no-root,
   behavior varies by distro/OEM.
2. **Userspace-only, no offload** — rejected: leaves performance on the table
   and complicates Android root mode where kernel NAT is well understood.
3. **eBPF/XDP-first** — rejected for v1: kernel/device support is uneven and
   it would exclude unrooted Android entirely.
