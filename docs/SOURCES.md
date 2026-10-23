# Sources & Further Reading

All URLs checked 2026-10-22.

## Our own codebases

- SoftEtherVPN Zig port (local): `~/Documents/SoftEtherVPN` @ `f20c61a`
- SoftEtherVPN on GitHub: <https://github.com/devstroop/SoftEtherVPN> (redirects to `devstroop/SE`) @ `8f6d657`
- Key files studied:
  - `src/cedar/server/nat.zig` — outbound socket-per-flow NAT
  - `src/cedar/server/securenat.zig` — DHCP + ARP + NAT orchestrator
  - `src/mayaqua/network/udp_accel.zig` — RUDP / NAT-T
  - `src/adapter/{tun_linux,utun,tap_windows,fd_adapter,route}.zig`
  - `docs/rca/UDP_ACCELERATION_RUDP.md` — NAT traversal gaps
  - `AGENTS.md`, `README.md` — platform matrix and danger zones

## Zig

- Zig 0.16.0 release notes — <https://ziglang.org/download/0.16.0/release-notes.html>
  - I/O as an Interface, `std.process.Init`, `@cImport` deprecation, `@Type` removal,
    Windows networking without ws2_32, `std.Io.net`, target minimums.
- Zig 0.17.0 release notes — <https://ziglang.org/download/0.17.0/release-notes.html>
  - Language stability, `@bitCast`, build-system cache rework, LLVM 22, glibc 2.44.
- Zig download index — <https://ziglang.org/download/index.json>
- Zig 0.16 std library (local): `~/.native/toolchains/zig-0.16.0/lib/std`

## Prior art / product analogs

- VNT — <https://github.com/vnt-dev/vnt>
  - Docs: <https://rustvnt.com>
  - DeepWiki: <https://deepwiki.com/vnt-dev/vnt>
- `rustp2p-core` (NAT detection/P2P core used by VNT) — see VNT `Cargo.toml` deps
- Tailscale — how NAT traversal works:
  <https://tailscale.com/blog/how-nat-traversal-works>
- Tailscale — how Tailscale works (control plane, DERP):
  <https://tailscale.com/blog/how-tailscale-works>
- WireGuard protocol — <https://www.wireguard.com/protocol/>
- Wintun (Windows TUN) — <https://www.wintun.net/> and
  <https://git.zx2c4.com/wintun/about/>
- floo (Zig tunneling) — <https://github.com/YUX/floo>
- zig-libp2p (Circuit Relay v2 / DCUtR) — <https://github.com/blockblaz/zig-libp2p>
- OpenConnect / ocserv (TLS VPN prior art) — <https://www.infradead.org/openconnect/>
- Netbird — <https://github.com/netbirdio/netbird>
- ZeroTier — <https://github.com/zerotier/ZeroTierOne>
- n2n — <https://github.com/ntop/n2n>
- EasyTier — <https://github.com/EasyTier/EasyTier>

## NAT / networking standards

- RFC 791 — Internet Protocol (IPv4)
- RFC 792 — Internet Control Message Protocol
- RFC 826 — An Ethernet Address Resolution Protocol (ARP)
- RFC 1191 — Path MTU Discovery
- RFC 1624 — Computation of the Internet Checksum via Incremental Update
- RFC 4787 — NAT Behavioral Requirements for Unicast UDP
- RFC 5382 — NAT Behavioral Requirements for TCP
- RFC 5508 — NAT Behavioral Requirements for ICMP
- RFC 8489 — Session Traversal Utilities for NAT (STUN)
- RFC 8656 — Traversal Using Relays around NAT (TURN)
- RFC 8445 — Interactive Connectivity Establishment (ICE)
- RFC 6886 — NAT Port Mapping Protocol (NAT-PMP)
- RFC 6887 — Port Control Protocol (PCP)
- RFC 9000/9001/9002 — QUIC transport + TLS + loss detection
- RFC 8439 — ChaCha20 and Poly1305
- RFC 7748 — X25519 / X448
- RFC 8032 — Ed25519
- RFC 5869 — HKDF
- RFC 8200 — IPv6
- RFC 6146 — NAT64
- UPnP IGD — <https://openconnectivity.org/developer/specifications/upnp-resources/upnp/internet-gateway-device-igd-v-2-0/>

## Platform APIs

### Linux
- `tun`/`tap` kernel docs: <https://www.kernel.org/doc/Documentation/networking/tuntap.txt>
- rtnetlink: `man 7 rtnetlink`
- nftables NAT: <https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)>
- io_uring: <https://kernel.dk/io_uring.pdf>
- `tc-netem`: <https://man7.org/linux/man-pages/man8/tc-netem.8.html>

### Android
- `VpnService` reference: <https://developer.android.com/reference/android/net/VpnService>
- `VpnService.Builder`: <https://developer.android.com/reference/android/net/VpnService.Builder>
- VPN developer guide: <https://developer.android.com/develop/connectivity/vpn>
- Always-on VPN: <https://developer.android.com/work/dpc/vpns>
- JNI tips: <https://developer.android.com/training/articles/perf-jni>
- Foreground services: <https://developer.android.com/develop/background-work/services/fgs>

### macOS / iOS
- `NEPacketTunnelProvider`: <https://developer.apple.com/documentation/networkextension/nepackettunnelprovider>
- `NEPacketTunnelNetworkSettings`: <https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings>
- Network Extension entitlements: <https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>
- `utun` control interface: XNU `bsd/net/if_utun.h` / `sys/kern/uipc_sysctl.c`
- `PF_ROUTE` routing socket: `man 4 route`

### Windows
- Wintun API: <https://git.zx2c4.com/wintun/about/> (see README reference)
- Wintun releases: <https://www.wintun.net/builds/>
- `CreateIpForwardEntry2`: <https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2>
- `SetInterfaceDnsSettings`: <https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings>
- `New-NetNat`: <https://learn.microsoft.com/en-us/powershell/module/ninnetnat/new-netnat>
- WFP: <https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page>

## Zig ecosystem (evaluate, don't depend yet)

- zquic — <https://github.com/zigstack/zquic>
- quic (devnw) — <https://gitlab.com/devnw/zig/quic>
- tls (devnw) — <https://gitlab.com/devnw/zig/tls>
- zigtls — <https://github.com/Geun-Oh/zigtls>
- colibri (HTTP/1.1/2/3) — <https://zigpkg.dev/packages/c4milo/colibri>
- quic-zig — <https://github.com/endel/quic-zig>
- zig-libp2p — <https://github.com/blockblaz/zig-libp2p>

## Anthropic skills

- Repository: <https://github.com/anthropics/skills>
- Installed into this project (`.opencode/skills/`):
  - `skill-creator` (Apache-2.0) — create/optimize project skills
  - `doc-coauthoring` — structured specs / ADRs / proposals
  - `webapp-testing` (Apache-2.0) — Playwright-based UI testing for the future
    control-plane dashboard
- Deliberately not installed: `docx`, `pdf`, `pptx`, `xlsx` (proprietary
  licenses), `brand-guidelines`, `theme-factory`, `canvas-design`,
  `algorithmic-art`, `slack-gif-creator`, `web-artifacts-builder`,
  `internal-comms`, `academy-guide`, `discernment-nudge`, `claude-api`,
  `mcp-builder`, `frontend-design`.
- Spec for the Agent Skills format: <https://agentskills.io>
