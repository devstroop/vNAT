# ADR-010 — Embedded C ABI and host fd injection

- **Status:** Accepted (R7 foundation)
- **Date:** 2026-10-24

## Context

Android `VpnService` gives the host app one L3 TUN descriptor after
`Builder.establish()`. The Zig core cannot open that descriptor itself, and the
app is not allowed to expose JNI types to the core. A host must therefore:

- pass a validated configuration,
- inject the `VpnService` descriptor,
- start and stop the data plane, and
- receive lifecycle state without calling into Java per packet.

The daemon already had the required lifecycle inline in `exec/vnatd/main.zig`.
Duplicating it in a second host path would drift, so the lifecycle was extracted
into `src/app/service.zig` and both `vnatd` and the C ABI use it.

## Decision

Expose a versioned C ABI in `src/ffi.zig` and `include/vnat.h`:

- Opaque `vnat_t`, fixed-width status struct, stable error codes and event
  codes. `VNAT_ABI_VERSION` is 1.
- `vnat_create` parses and validates JSON. It accepts configured existing L3
  ports (`kind = "l3"`, no `create`) so the host can bind a descriptor.
- `vnat_set_port_fd` binds a host-owned descriptor to a named L3 port before
  startup. The descriptor is borrowed; vNAT duplicates it with
  `F_DUPFD_CLOEXEC` during `vnat_start`, so the host can close the original
  after startup. The duplicate is set non-blocking, which also affects the
  original descriptor because both share one open file description. A stopped
  handle reuses its bindings when restarted, so the descriptor must remain
  valid for every `vnat_start`. Only L3 ports without `create` are eligible.
- `vnat_start` blocks until the service is ready or startup fails.
  `vnat_stop` is idempotent and joins the data-plane thread. `vnat_destroy`
  stops first and then releases native resources; it must not be called from
  an event callback.
- Events are delivered on the data-plane thread. `STARTED` is delivered
  before `vnat_start` returns. Callbacks must not call `vnat_*` functions other
  than `vnat_get_status`; `vnat_stop` and `vnat_destroy` would deadlock.
- The FFI profile disables host mutations and hotplug monitoring
  (`allow_host_changes = false`, `enable_monitor = false`) and does not write
  daemon counter snapshots. A configured kernel offload requiring host
  mutation fails with `VNAT_ERR_UNSUPPORTED` instead of silently falling back.
- The library is built from `src/ffi.zig`; the CLI/daemon are built from
  `src/lib.zig`. The FFI module uses host pthreads for its service and DNS
  worker threads, without linking libc. It does not use Zig's raw-clone thread
  path, which cannot establish a libc TCB inside a host process. The FFI
  profile must not use `std.Io.concurrent`; it uses `src/thread.zig`.
- `test/ffi_smoke.c` compiles against the installed header, links the shared
  library, and exercises create/status/fd-injection/start/stop/destroy.

## Consequences

- The host app owns the `VpnService` descriptor and lifecycle; the core owns
  packet processing.
- The shared library leaves its pthread and host TLS/auxv references
  (`pthread_create`, `pthread_join`, `__tls_get_addr`, `getauxval`) undefined.
  Android bionic and glibc provide them; Linux consumers of an older libc must
  link `-pthread`. The static library likewise relies on the host's pthread
  implementation.
- JNI, the Android foreground service, `onRevoke`, network changes and proxy
  NAT remain host/R7 work. This ADR covers the native ABI foundation only.
- ABI changes require a header update, a version bump and a changelog entry.

## Alternatives

- **JNI-only API**: couples the core to Java and prevents desktop/other hosts.
- **Zig-owned raw-clone threads**: avoids libc, but crashes when the library is
  loaded by a C host because the host TLS/TCB is not initialized.
- **Run the daemon as a separate process**: viable on Linux root mode, but
  cannot share a `VpnService` descriptor without extra IPC.
- **Link libc into the library**: works on glibc but makes Android cross-builds
  depend on an NDK sysroot and does not solve the static-library contract.
