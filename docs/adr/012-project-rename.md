# ADR-012 — Rename vNAT to vRouter

- **Status:** Accepted
- **Date:** 2026-10-24

## Context

The project was named vNAT when its first milestone focused on address
translation. It has since become a portable router: userspace L2 bridging, L3
forwarding, conntrack/NAT, DHCP, DNS, firewall and a journaled host control
plane. The old name describes one subsystem and no longer matches the product
or its documentation.

The project is pre-1.0 and has no released ABI or installed base to preserve.
Keeping two names would add permanent aliases to the C ABI, CLI, paths and
tests, and would make future documentation ambiguous.

## Decision

Rename the project to **vRouter** and make the rename a clean break:

1. **Product and documentation.** Use `vRouter` in prose and `vrouter` in
   commands, identifiers, paths and package names.
2. **Executables and artifacts.** `vnat` becomes `vrouter`, `vnatd` becomes
   `vrouterd`, and the post-v1 `vnat-web` becomes `vrouter-web`. Library and
   package names use `vrouter`.
3. **C ABI.** `include/vnat.h` becomes `include/vrouter.h`; exported functions
   become `vrouter_*`; types, enum values and macros become `vrouter_*` /
   `VROUTER_*`. The status struct layout and lifecycle semantics are unchanged,
   but the symbol namespace change is a breaking ABI event, so
   `VROUTER_ABI_VERSION` becomes 2.
4. **Paths and environment.** Defaults become `/run/vrouter`,
   `/etc/vrouter/vrouter.json` and `<state_dir>/vrouterd.log`; environment
   variables use the `VROUTER_` prefix. Socket and lock file names remain
   `control.sock`, `control.sock.lock` and `control.sock.up.lock` inside the new
   run directory.
5. **No compatibility aliases.** v0.1.0 does not ship `vnat` symlinks,
   forwarding C symbols or duplicated paths. A compatibility layer would need
   to be maintained indefinitely and there are no released consumers.
6. **Migration is explicit.** Operators upgrading from a pre-rename build must
   stop the old daemon and run the old `vnat down` before installing vRouter.
   Journals and runtime state under `/run/vnat` are not migrated automatically
   because they describe host state that must be reconciled, not copied.
7. **Repository hosting is separate.** Renaming the GitHub repository or remote
   URL is an operational follow-up; it is not required for the source rename.

## Consequences

- The source, binaries, C header, environment variables and default paths share
  one consistent name.
- Existing local scripts, configs that reference the old run directory, and
  hosts linked against the old C ABI must be updated.
- A pre-rename daemon must be stopped with the old CLI so its journal can undo
  host changes before the new paths are used.
- The rename is recorded as a breaking change in `CHANGELOG.md` and the project
  version moves to 0.1.0.

## Alternatives

- **Keep vNAT.** Accurate for the NAT subsystem but misleading for the product.
- **Keep vNAT and add vRouter aliases.** Preserves old scripts, but doubles the
  public surface and permanently anchors the old name.
- **Rename only the product, not the ABI or paths.** Avoids a breaking release
  but leaves `vnat` identifiers in the code and documentation, which defeats
  the purpose of the rename.
