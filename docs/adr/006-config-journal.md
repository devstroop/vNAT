# ADR-006 — Configuration and journal formats

- **Status:** Accepted (R2 subset; batch apply in R7)
- **Date:** 2026-10-22

## Context

vRouter mutates host state: addresses, routes, links, bridge membership, NAT and
firewall rules, Android tethering. A crash or `kill -9` must not leave the
device blackholed or leaking traffic. The control plane also needs to diff
configs, apply them transactionally, and be inspectable without a database.

## Decision

### Configuration

- UTF-8 **JSON**, schema version `1`, strict:
  - unknown fields are errors at every level;
  - duplicate keys are errors;
  - no comments, no trailing commas;
  - all limits and defaults are documented in `docs/CORE-SCOPE.md`.
- Parsed into an arena-owned typed model (`src/config/`). Validation is a
  separate pass so `vrouter validate` can report schema errors without touching
  the host.
- A config diff is computed on the typed model, not on text. Key order and
  whitespace never affect the diff.
- Secrets (none in v1) would be referenced by path/env, never inlined.

### Journal (R2 implementation)

- JSON Lines, one **forward operation** per line, under
  `$VROUTER_RUN_DIR/<instance>.journal` (default `/run/vrouter/<instance>.journal`).
- Operations: `addr_add`, `addr_del`, `link`, `route_add`, `route_del`.
- Sequence:
  1. Write the line with an atomic temp-file rename and `fsync`.
  2. Apply the netlink/ioctl mutation.
  3. On failure, remove the line so rollback cannot touch pre-existing state.
- `vrouter down` reads records and applies the inverse in reverse order:
  add↔delete, link up↔down. "Already absent" on delete and "already exists" on
  add count as restored.
- `iface del` and `route del` are ownership-gated by replaying the journal:
  state that vRouter did not add is never removed.
- A crash between (1) and (2) leaves an idempotent record that `vrouter down`
  cleans up. A fully successful rollback removes the journal; failures keep it
  so the operation can be retried.
- `/run` is deliberate: host state is ephemeral across reboot, and a persistent
  journal would reference addresses/routes that no longer exist.
- The journal contains no secrets.

### Future (R7 control plane)

- `pending`/`applied` status, sequence numbers and timestamps for audit.
- Batch apply for `vrouter up`: write all records, then apply; roll back on the
  first failure.
- PID lock per instance and reconciliation at daemon startup.
- `vrouter doctor --repair` for drift and stale records.

### Atomic apply

- R2 applies one mutation per CLI command, journaling it first.
- R7 computes the full config diff, validates it, writes all records, then
  applies. If any mutation fails, it applies the inverses already recorded in
  reverse order and returns a typed error identifying the failing step.
- No partial "best effort" apply.

## Consequences

- R2 recovery is deterministic for single mutations; R7 extends it to batched config apply and `kill -9` fault injection.
- The journal is human-readable and easy to attach to bug reports.
- `fsync` per mutation costs latency, but applies are rare (config changes,
  link events), not per-packet.
- JSONL is not a database: no concurrent writers, no queries. That is
  intentional.

## Alternatives considered

1. **SQLite** — durable and transactional, but adds a dependency and hides the
   inverse semantics; overkill for a handful of mutations.
2. **In-memory only** — loses state on crash; unacceptable for tethering.
3. **Netlink transaction batches** — not atomic across address/route/bridge
   changes and unavailable on Android.
4. **`nft` ruleset snapshots** — backend-specific and not portable.
