# ADR-011 — Optional local web admin

- **Status:** Accepted (post-v1, R10)
- **Date:** 2026-10-24

## Context

v1 is deliberately headless: the daemon, CLI and Unix-socket API are the only
interfaces, and Android hosts render their own UI over the C ABI. On a Linux
appliance, however, an operator may want to inspect status, leases, counters
and journal state, and eventually apply small configuration changes, without
SSH or remembering CLI flags.

A web admin must not weaken the existing contract:

- The daemon remains the only component that mutates host state.
- The web process must not need root, `CAP_NET_ADMIN` or direct netlink access.
- Deployments are offline, single-binary friendly and must not require Node.
- Browser access is hostile input: authentication, CSRF, origin checks and
  output escaping are mandatory.
- v1 scope is unchanged. The feature ships only after the control API and
  release hardening are stable.

## Decision

Add an **optional, post-v1 local web admin for Linux**:

1. **Separate unprivileged adapter.** `vnat-web` is a standalone executable
   (planned `exec/vnatweb`, `src/web/`), not part of the core library or
   `vnatd`. It speaks the same line-delimited JSON Unix-socket API as the CLI.
   It never opens ports, writes journals, calls netlink or edits config files
   directly.
2. **Privilege separation.** `vnatd` remains the sole mutator. The web process
   runs as an unprivileged service account in the `vnat` group and uses the
   control socket (`0660`, peer credentials). Read and write capabilities are
   distinct API scopes; a read-only deployment must not receive write access.
3. **Server-rendered HTMX.** The UI is server-rendered HTML with templates and
   assets embedded via `@embedFile`. HTMX is vendored and version-pinned; no
   CDN, Node runtime, package manager or frontend build step. Plain CSS and
   progressive enhancement only; no SPA framework.
4. **HTTP transport.** Default to `127.0.0.1` or a Unix socket. A wildcard or
   LAN bind is explicit opt-in and must sit behind TLS termination (Caddy,
   nginx or equivalent). The initial web adapter does not need to implement TLS
   itself. Plain HTTP must never listen on a non-loopback address.
5. **Authentication and browser hardening.** Require a local account (PAM or
   Argon2id password) with server-side sessions. Use `HttpOnly`,
   `SameSite=Strict` and `Secure` cookies under TLS, per-session CSRF tokens,
   `Origin`/`Host` validation, login rate limits, strict CSP with no inline
   script, `frame-ancestors 'none'`, and an audit log for writes. Loopback is
   not treated as an authentication boundary.
6. **Read-only first.** R10 phase one exposes status, ports, bridges, routes,
   leases, conntrack, counters, firewall rules and journal. Phase two adds
   validated config apply with diff/preview/confirm/rollback, plus link
   up/down and reconnect. No arbitrary shell, file browser or raw netlink
   escape hatch.
7. **No new source of truth.** The daemon's control API and config validation
   remain authoritative. If a UI action needs a new operation, extend the
   versioned control API; do not duplicate logic in the web layer.
8. **No telemetry or cloud.** No cloud accounts, analytics, remote logging or
   outbound connections except the configured control socket.
9. **Testing.** Handlers and authorization get unit tests; happy paths and
   security negatives (auth bypass, CSRF, origin/host confusion, path
   traversal, template escaping, session fixation, rate limits) get
   Playwright coverage using the `webapp-testing` skill.

## Consequences

- Linux operators get an optional browser workflow without adding a Node
  runtime or a privileged web process to the appliance.
- The project gains a second package/binary, an authentication surface and
  browser-facing security maintenance. This is why it is post-v1 and optional.
- The control socket must be stable and support read/write scopes before R10
  starts. UI features cannot outrun the API.
- The web UI can be unavailable or restarted without affecting forwarding.
- The feature is Linux-only and local/single-node; Android continues to use
  its native host UI over the C ABI. Remote multi-router management, SSO and
  cloud control remain non-goals and would require a separate product/ADR.

## Alternatives

- **Next.js / React SPA:** rejected for the appliance. It adds a Node runtime,
  a build pipeline, a larger dependency surface and an unnecessary client-side
  state layer. It could be appropriate for a future hosted multi-router
  controller, which is explicitly out of scope.
- **Embed the HTTP server in `vnatd`:** rejected. It would put browser parsing
  and session state in the privileged daemon.
- **HTMX from a CDN:** rejected. Offline deployments cannot depend on a third
  party, and the CSP should remain `self`-only.
- **TUI or more CLI verbs:** retained as the primary interface. The web admin
  is additive, not a replacement.
- **Web process with direct netlink/journal access:** rejected. It would
  duplicate validation and defeat privilege separation.
