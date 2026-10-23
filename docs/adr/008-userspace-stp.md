# ADR-008 — Userspace 802.1D STP for bridged ports

**Status:** Accepted (R5)
**Date:** 2026-10-24

## Context

A looped L2 topology floods frames forever. Storm control limits the damage
but does not elect a loop-free tree. Linux bridge offload is deferred, so the
userspace bridge needs its own loop prevention when `bridge.stp` is enabled.

## Decision

Implement basic 802.1D configuration BPDUs in `src/l2/stp.zig` and run one
shared STP instance per userspace bridge:

- Bridge ID uses priority `0x8000` and the lowest non-zero member MAC
  (synthetic `02:...` if no member has a MAC).
- Every port starts blocking, listens for 15 s, learns for 15 s, then
  forwards. Alternate ports stay blocking.
- Designated ports transmit configuration BPDUs every 2 s; received BPDUs
  refresh the root vector. BPDUs older than 20 s are ignored.
- Link-local frames to `01:80:c2:00:00:00` are consumed before VLAN
  classification and are never bridged.
- The bridge datapath learns only on learning/forwarding ports and forwards
  only to forwarding ports. Ingress frames on blocking/listening ports are
  dropped and counted as `stp_filtered`.

Port cost is fixed at 19 (100 Mbit/s reference). BPDUs are untagged and the
instance is shared across all VLANs on the bridge. RSTP, per-port priorities,
and topology-change-driven FDB flushes are out of scope for this milestone.

## Consequences

- Loops are broken without host/kernel bridge setup; `bridge.stp = true` is
  now accepted by the validator.
- Bridged data is unavailable on a port for up to 30 s after startup or a
  topology change. Small trusted topologies should leave STP off.
- STP frames are generated in the userspace loop, so a stalled scheduler can
  delay hellos; the 20 s max age tolerates short stalls.
- Kernel bridge offload remains rejected and can later replace this instance
  behind the same configuration key.
