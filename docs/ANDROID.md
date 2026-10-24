# vRouter — Android Platform Notes

> Android is the hardest platform constraint in this project. This document
> separates what is possible **without root** from what requires **root**, and
> defines the two supported modes.
> Companion: [CORE-SCOPE.md](./CORE-SCOPE.md), ADR-003.

---

## 1. The hard truth about Android

An unprivileged Android app **cannot** open `AF_PACKET`, create TUN/TAP
devices, modify routes, or change iptables. The only sanctioned packet path is
`VpnService`, which gives the app **one L3 TUN file descriptor for its own user
profile's traffic**.

Consequences:

| Goal | No root | Root |
|---|---|---|
| Route/NAT the device's own app traffic | ✅ `VpnService` | ✅ |
| Per-app include/exclude | ✅ Builder APIs | ✅ |
| DNS control for the VPN | ✅ `addDnsServer` | ✅ |
| Kill switch / always-on | ✅ system settings + app support | ✅ |
| L2 bridging | ❌ | ✅ `AF_PACKET` |
| DHCP server for other devices | ❌ | ✅ |
| Route **hotspot / USB-tethered clients** | ❌ | ✅ (with interception) |
| Port forwarding from the mobile network | ❌ (carrier NAT) | ⚠️ depends on carrier |
| Create a hotspot/AP from the app | ❌ (system API) | ⚠️ OEM/root only |
| Use USB-C Ethernet as an uplink | ✅ visible to the OS; usable via protected sockets for app traffic | ✅ raw port access |

**Therefore vRouter on Android has two modes:**

- **Mode A — VPN router (no root).** A router/NAT/firewall for the device's own
  traffic, with a protected uplink socket. This is shippable on Play Store.
- **Mode B — Portable router (root).** Full L2/L3 interfaces, bridging, DHCP,
  NAT and interception of tethered clients. Distributed outside Play Store.

The core is identical; only the port backends and capabilities differ.

---

## 2. Mode A — VPN router (no root)

### 2.1 Topology

```
app traffic ──▶ VpnService TUN (fd) ──▶ vRouter core ──▶ protected UDP/TCP sockets ──▶ uplink
                                          │
                                          └─ DNS responder, firewall, per-app policy
```

- vRouter owns the TUN fd; all apps in the VPN profile are routed into it
  according to `Builder` routes.
- vRouter terminates/forwards packets and emits them through **protected**
  sockets, which bypass the VPN (otherwise loops).
- NAT here is socket-per-flow (conntrack + per-flow socket), not packet-level
  forwarding, because the uplink is a socket, not a raw interface.
  - TCP: accept/connect proxy per flow (userspace splice).
  - UDP: per-flow UDP socket with timeout.
  - ICMP: echo proxy (best effort).
- Alternatively, if the goal is only to *shape* traffic and the OS should do
  NAT, vRouter can be configured as a transparent forwarder — but the default is
  vRouter-owned NAT so DNS/firewall/port policy is consistent.

### 2.2 `VpnService` setup

```java
VpnService.Builder b = new Builder();
b.setSession("vRouter");
b.setMtu(1380);
b.addAddress("10.26.0.2", 24);
b.addRoute("0.0.0.0", 0);            // full tunnel; omit for split
b.addRoute("fd76:6e74::", 96);       // virtual IPv6, if used
b.addDnsServer("10.26.0.1");
b.setBlocking(true);                 // blocking fd reads; NOT a kill switch
b.addDisallowedApplication("com.example.bank"); // split tunnel
ParcelFileDescriptor pfd = b.establish(); // may return null
int fd = pfd.detachFd();
```

Rules:
- `addAddress` does **not** create a route — always add the virtual subnet
  route explicitly.
- Only add `0.0.0.0/0` (and `::/0`) for full-tunnel mode.
- `setMtu(1380)` is the safe default; never exceed the uplink MTU minus
  overhead.
- `protect(fd/socket)` every socket used for the uplink.
- `setUnderlyingNetworks()` to declare the physical network; update on change.
- `establish()` can return `null` (another VPN, permission, system policy).
- `onRevoke()` must stop the data loop and close the fd.
- One active VPN per user; be prepared to lose to another app.

### 2.3 Native lifecycle and fd ownership

The native library implements the C ABI in `include/vrouter.h` (see ADR-010).
The config must declare an existing L3 port (for example `vpn0`) with
`"kind": "l3"` and no `create`:

1. `vrouter_create(config_json)` — parse and validate.
2. `vrouter_set_port_fd(handle, "vpn0", fd)` — bind the `establish()` descriptor
   before startup.
3. `vrouter_start(handle)` — blocks until the data plane is ready; vRouter duplicates
   the fd, so the app may close its copy after this returns. Restarting the
   same handle reuses the binding, so keep the fd open if a restart is planned.
4. `onRevoke()` / service shutdown — `vrouter_stop(handle)`, then close the VPN
   interface and destroy the handle.

Events are delivered on the data-plane thread. Callbacks must not call
`vrouter_*` functions other than `vrouter_get_status`. The FFI profile does not mutate host state or start
hotplug monitoring. The shared library calls the platform's `pthread_create` /
`pthread_join`; Android bionic provides them, while Linux static consumers
should link with `-pthread`.

### 2.4 Lifecycle and permissions

- Service extends `VpnService`, declared with `android:permission="BIND_VPN_SERVICE"`
  and exported only as required.
- Start from a user action; Android 10+ restricts background starts.
- Foreground service while running:
  - `startForeground()` with a persistent notification.
  - Android 14+: declare a `foregroundServiceType`; VPN apps use
    `specialUse` with the required `<property>` subtype, or `systemExempted`
    where applicable. Check the current Play policy before release.
  - Android 13+: request `POST_NOTIFICATIONS`.
- Handle `ConnectivityManager.NetworkCallback`:
  - on network change, re-evaluate the uplink, update underlying networks,
    flush conntrack tied to the old network, reconnect protected sockets.
- Doze/App Standby: foreground service + `WakeLock` only while forwarding;
  batch timers; no per-packet wakeups.

### 2.5 DNS

- Advertise the router address via `addDnsServer`; vRouter answers locally and
  forwards upstream over protected sockets.
- Android **Private DNS** (DoT) can bypass the VPN's DNS on some versions;
  document this and offer "block DoT" via firewall rules if the user opts in.
- IPv6 DNS (`addDnsServer` with a v6 address) supported on modern Android.

### 2.6 Limits of Mode A

- Cannot serve tethered clients.
- Cannot use raw L2; no bridging.
- Throughput bound by userspace proxy + fd copies.
- Some apps bypass VPN (e.g. certain system components, always-on conflicts).
- Cellular carriers may block inbound; port forwarding is unreliable.

---

## 3. Mode B — Portable router (root)

### 3.1 Capabilities unlocked

- `AF_PACKET` on `wlan0`, `ap0`, `swlan0`, `usb0`, `rndis0`, `bt-pan`,
  `rmnet_data*`, `ccmni*`, `radio*`, `eth0`.
- **Caveat:** whether `AF_PACKET` sees frames on an AP-mode interface is
  driver-dependent (some Wi-Fi drivers deliver 802.11 management/data only
  through `nl80211`, and some drop frames before the packet socket). Probe per
  device and report honestly; do not assume `ap0` is a usable L2 port.
- Create TUN/TAP.
- Netlink: addresses, routes, neighbors, link state.
- `iptables`/`ip6tables` or `nft`; `tc`; `ip rule`.
- Possibly network namespaces (kernel-dependent).
- Intercept tethered clients.

### 3.2 Becoming the router for tethered clients

When Android enables hotspot/USB tethering it installs its own forwarding +
NAT rules (netd/`tetherctrl`, and on newer versions BPF offload). To make vRouter
the router you must displace that data path. Three strategies:

**Strategy 1 — Control-plane takeover (recommended for v1 root mode).**
- Keep the kernel as the fast path, but replace the tethering NAT/forwarding
  with vRouter-owned rules:
  - `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`
  - remove/disable the tethering MASQUERADE rules for the target interface
  - add vRouter's own SNAT/DNAT/firewall rules
- vRouter owns DHCP/DNS/NAT policy; the kernel forwards.
- Pros: fast, simple, robust. Cons: not a userspace datapath; depends on
  iptables/nft availability and OEM behavior.

**Strategy 2 — Userspace interception via NFQUEUE.**
- `iptables -I FORWARD -i <tether> -j NFQUEUE --queue-num N`
- vRouter receives packets, routes/NATs them in userspace, reinjects via raw
  sockets/TUN.
- Pros: true userspace router; full control. Cons: performance, queue bypass
  risks (fail-open), kernel config dependency (`NFQUEUE`), OEM variation.

**Strategy 3 — L2 capture with `AF_PACKET` + suppress kernel path.**
- Capture frames on the tethered interface; drop/steal them from the kernel
  with eBPF/XDP or netfilter.
- Pros: true L2 bridging. Cons: needs eBPF/XDP support, complex, fragile on
  Android kernels; treat as experimental.

**v1 root mode implements Strategy 1** (control-plane takeover) plus an
`intercept = "nfqueue"` experimental flag for Strategy 2. Strategy 3 is
post-v1.

### 3.3 Rollback is mandatory

Root mode mutates global state. Requirements:
- Journal every rule/route/sysctl change with its inverse.
- On stop/crash/reboot: restore tethering rules, forwarding flags and routes.
- `vrouter doctor` detects a dirty state after a crash and offers `--repair`.
- Never leave the device without working tethering.

### 3.4 SELinux and root managers

- Root via Magisk / KernelSU / APatch; `su -c` or a privileged helper.
- SELinux may deny `AF_PACKET`, netlink, or iptables even as root:
  - use the root manager's su domain;
  - ship a small `vrouterd` helper started by `su` with a permissive domain or
    `magiskpolicy` rules if needed;
  - detect denials (`dmesg`/`logcat` avc) and report actionable errors.
- Android 10+ `su` restrictions; some OEMs (Samsung Knox) are hostile.

### 3.5 Interface discovery

- Enumerate via `ConnectivityManager` (host) + netlink (native).
- Map logical roles to devices by config, with stable matching:
  - MAC address (preferred)
  - interface name
  - driver/kind
- Handle name churn (`rmnet_data0` → `rmnet_data1`), carrier changes, and
  Wi-Fi ↔ cellular handover.
- Hotspot interfaces appear/disappear with tethering; watch netlink.

### 3.6 Power and thermals

- Multi-core forwarding is power-hungry; default to 2 workers, scale by load.
- Suspend forwarding when screen off only if configured (routers usually must
  stay on).
- Thermal throttling: measure and back off batching.

---

## 4. Host app responsibilities (thin by design)

The Android app is a shell; it must not contain routing logic.

| Concern | Host (Java/Kotlin) | Core (Zig) |
|---|---|---|
| VPN consent / Builder | ✅ | — |
| `establish()` / fd | ✅ | receives fd |
| Protect uplink sockets | ✅ (pass via JNI or callback) | uses them |
| Connectivity callbacks | ✅ | receives events |
| Foreground service | ✅ | — |
| Root `su` invocation | ✅ | requests capabilities |
| Config UI (later) | ✅ | validates |
| Routing/NAT/DHCP/DNS | — | ✅ |
| Interface enumeration (root) | — | ✅ netlink |
| Status/metrics | renders | produces |

JNI rules:
- `System.loadLibrary("vrouter")`.
- Keep native methods small; pass `int fd`, `String`, `byte[]`.
- Never call back into Java per packet.
- Attach native threads before calling Java.
- Version the native API (`vrouter_jni_version()`), check on load.

---

## 5. Testing matrix

| Test | Environment |
|---|---|
| VPN mode, full tunnel | Emulator API 30–36 |
| VPN mode, split tunnel | Emulator + real apps |
| Network switch Wi-Fi↔LTE | Emulator (network profiles) + physical |
| Revoke / another VPN | Emulator |
| Always-on + lockdown | Emulator/system settings |
| Doze/battery | Physical device, 8 h |
| Root mode, hotspot clients | Rooted device (Magisk) + laptop |
| Root mode, USB tethering | Rooted device + USB-C Ethernet dongle |
| Root mode, rollback | Kill -9 during run, reboot, `vrouter doctor` |
| OEM variance | Samsung, Xiaomi, Pixel, OnePlus if available |

CI: emulator smoke on every PR (VPN mode). Root tests are nightly/manual.

---

## 6. Distribution

| Mode | Channel | Notes |
|---|---|---|
| VPN (no root) | Play Store, F-Droid, APK | Declare VpnService use; privacy policy; no deceptive behavior |
| Root router | GitHub Releases, F-Droid (if policy allows), sideload | Clearly labeled; not on Play Store |
| Native lib | AAR with `arm64-v8a`, `armeabi-v7a`, `x86_64` | Match ABI to device; include 16 KB page-size alignment for Android 15+ |

Play policy reminders:
- VPN apps must use `VpnService` and disclose data handling.
- No use of VPN for ad blocking/redirecting other apps' traffic without
  disclosure.
- Root mode must never be silently enabled.

---

## 7. Decision points (need sign-off)

1. **Is root mode in v1 scope?** Recommended: yes, but as a separate binary /
   build flavor, with Strategy 1 only.
2. **Does the product need to serve tethered clients in v1?** If no, Android
   can ship as Mode A only and root mode slips to v1.1.
3. **Play Store first or sideload first?** Play Store constrains root mode and
   forces a privacy review.
4. **Cellular uplink:** do we need to support `rmnet` as an L2 port, or is
   socket-based uplink sufficient? (Raw cellular L2 is rarely useful without
   carrier cooperation.)
