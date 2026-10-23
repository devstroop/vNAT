#!/usr/bin/env bash
# Kernel-bridge offload parity test: VLAN-aware kernel bridge, veth trunk into
# the userspace datapath, L2/SVI/DHCP/routing/NAT, kernel STP, and rollback.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VNAT_OFFLOAD_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNAT_OFFLOAD_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNAT_OFFLOAD_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VNAT_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/offload.json"
CFG_STP="$WORK/offload-stp.json"
LOG="$WORK/vnatd.log"
LOG_STP="$WORK/vnatd-stp.log"

vpid=""
pidA=""
pidB=""
pidU=""

cleanup() {
    [ -n "$vpid" ] && kill -TERM "$vpid" 2>/dev/null || true
    if [ -f "$CFG" ] && [ -x "$BIN/vnat" ]; then
        "$BIN/vnat" down -c "$CFG" >/dev/null 2>&1 || true
    fi
    [ -n "$pidA" ] && kill "$pidA" 2>/dev/null || true
    [ -n "$pidB" ] && kill "$pidB" 2>/dev/null || true
    [ -n "$pidU" ] && kill "$pidU" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log() { printf '==> %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

for tool in ip unshare nsenter python3 ping timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat >"$CFG" <<'JSON'
{
  "version": 1,
  "instance": "offload-test",
  "ports": {
    "lan-a": { "kind": "l2", "device": "pa", "pvid": 10 },
    "lan-b": { "kind": "l2", "device": "pb", "pvid": 10 },
    "wan-p": { "kind": "l2", "device": "pw" }
  },
  "bridges": {
    "br": { "ports": ["lan-a", "lan-b"], "vlan_aware": true, "offload": "kernel" }
  },
  "interfaces": {
    "lan0": { "bridge": "br", "address": "10.30.40.1/24", "vlan": 10 },
    "wan0": { "port": "wan-p", "address": "192.0.2.1/24" }
  },
  "dhcp": [ { "iface": "lan0", "pool": "10.30.40.100-10.30.40.200", "lease": "1h" } ],
  "routes": [ { "dst": "0.0.0.0/0", "via": "192.0.2.2", "dev": "wan0" } ],
  "nat": { "masquerade": [ { "out": "wan0" } ] },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
JSON
sed 's/"vlan_aware": true,/"vlan_aware": true, "stp": true,/' "$CFG" >"$CFG_STP"

cat >"$WORK/dhcp_probe.py" <<'PY'
import fcntl
import socket
import struct
import sys
import time

iface = sys.argv[1]
raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind((iface, 0))
raw.settimeout(0.2)
mac = fcntl.ioctl(raw.fileno(), 0x8927, struct.pack("256s", iface.encode()))[18:24]

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
udp.bind(("0.0.0.0", 68))

xid = 0x3907A1C2
bootp = struct.pack(
    "!BBBBIHH4s4s4s4s16s64s128s",
    1, 1, 6, 0, xid, 0, 0x8000,
    b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
    mac + b"\0" * 10, b"", b"",
)
bootp += b"\x63\x82\x53\x63" + bytes([53, 1, 1, 55, 3, 1, 3, 6, 255])
udp.sendto(bootp, ("255.255.255.255", 67))

deadline = time.time() + 3
while time.time() < deadline:
    try:
        data, _ = raw.recvfrom(4096)
    except TimeoutError:
        continue
    if len(data) < 42 or data[12:14] != b"\x08\x00":
        continue
    ihl = (data[14] & 0x0F) * 4
    if len(data) < 14 + ihl + 8 or data[14 + 9] != 17:
        continue
    sport, dport = struct.unpack("!HH", data[14 + ihl:14 + ihl + 4])
    if sport != 67 or dport != 68:
        continue
    bootp_reply = data[14 + ihl + 8:]
    if len(bootp_reply) < 20 or bootp_reply[4:8] != struct.pack("!I", xid):
        continue
    yiaddr = socket.inet_ntoa(bootp_reply[16:20])
    if yiaddr == "0.0.0.0":
        continue
    print("offer", yiaddr)
    raise SystemExit(0)
print("no DHCP offer", file=sys.stderr)
raise SystemExit(1)
PY

log "topology"
ip link set lo up
ip link add pa type veth peer name ea || die "create veth pair pa/ea"
ip link add pb type veth peer name eb || die "create veth pair pb/eb"
ip link add pw type veth peer name ew || die "create veth pair pw/ew"

start_host() {
    local peer="$1" addr="$2" gw="$3" marker="$4"
    unshare -n bash -c '
        peer=$1; addr=$2; gw=$3; marker=$4
        while ! ip link show "$peer" >/dev/null 2>&1; do sleep 0.02; done
        ip link set "$peer" name eth0
        ip link set eth0 up
        ip link set lo up
        ip addr add "$addr/24" dev eth0
        if [ -n "$gw" ]; then ip route add default via "$gw"; fi
        touch "$marker"
        sleep 120
    ' _ "$peer" "$addr" "$gw" "$marker" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

pidA="$(start_host ea 10.30.40.2 10.30.40.1 "$WORK/a.ready")"
pidB="$(start_host eb 10.30.40.3 10.30.40.1 "$WORK/b.ready")"
pidU="$(start_host ew 192.0.2.2 "" "$WORK/u.ready")"

ip link set ea netns "$pidA" || die "move ea into host A"
ip link set eb netns "$pidB" || die "move eb into host B"
ip link set ew netns "$pidU" || die "move ew into upstream"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && [ -f "$WORK/u.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "host A did not configure"
[ -f "$WORK/b.ready" ] || die "host B did not configure"
[ -f "$WORK/u.ready" ] || die "upstream did not configure"
ip link set pw up || die "bring wan port up"
ok "clients 10.30.40.2/3 and upstream 192.0.2.2"

log "vnatd"
"$BIN/vnatd" -c "$CFG" >"$LOG" 2>&1 &
vpid=$!
for i in $(seq 1 100); do
    grep -q "started instance" "$LOG" && break
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG"
        die "vnatd exited"
    fi
    sleep 0.02
done
grep -q "started instance" "$LOG" || {
    cat "$LOG"
    die "vnatd did not start"
}

BR="$(sed -n 's/.*kernel=\([^ ]*\).*/\1/p' "$LOG" | head -1)"
TRUNK="$(sed -n 's/.*trunk=\([^ ]*\).*/\1/p' "$LOG" | head -1)"
BRIDGE_SIDE="vnatb${TRUNK#vnatp}"
[ -n "$BR" ] && [ -n "$TRUNK" ] || {
    cat "$LOG"
    die "missing offload device names"
}

log "kernel bridge"
ip -d link show dev "$BR" >"$WORK/bridge.txt" || die "kernel bridge missing"
grep -q "vlan_filtering 1" "$WORK/bridge.txt" || die "VLAN filtering not enabled"
grep -q "vlan_default_pvid 0" "$WORK/bridge.txt" || die "default PVID not cleared"
grep -q "master $BR" <<<"$(ip -o link show dev "$BRIDGE_SIDE")" ||
    die "veth bridge side is not enslaved"
ip -o link show dev pa | grep -q "state UP" || die "port pa is down"
ip -o link show dev pb | grep -q "state UP" || die "port pb is down"
ok "kernel bridge $BR with veth trunk $TRUNK"

log "bridge VLANs"
bridge vlan show >"$WORK/vlans.txt" || die "bridge vlan show failed"
grep -Eq '^pa[[:space:]]+10 PVID Egress Untagged' "$WORK/vlans.txt" ||
    die "pa is not PVID 10 untagged"
grep -Eq '^pb[[:space:]]+10 PVID Egress Untagged' "$WORK/vlans.txt" ||
    die "pb is not PVID 10 untagged"
grep -Eq "^${BRIDGE_SIDE}[[:space:]]+1 PVID Egress Untagged" "$WORK/vlans.txt" ||
    die "trunk is not PVID 1 untagged"
grep -Eq "^[[:space:]]+10$" "$WORK/vlans.txt" || die "trunk is not tagged VLAN 10"
ok "VLAN 10 access ports and tagged trunk"

log "L2 forwarding"
out="$(nsenter -t "$pidA" -n ping -c 1 -W 2 10.30.40.3 2>&1)" || {
    echo "$out"
    cat "$LOG"
    die "L2 ping failed"
}
echo "$out" | grep -q "ttl=64" || die "L2 ping was routed, not bridged"
ok "10.30.40.2 -> 10.30.40.3 through kernel bridge"

log "SVI"
nsenter -t "$pidA" -n ping -c 1 -W 2 10.30.40.1 >/dev/null ||
    die "SVI ping failed"
ok "10.30.40.2 -> 10.30.40.1 over veth trunk"

log "DHCP"
offer="$(nsenter -t "$pidA" -n python3 "$WORK/dhcp_probe.py" eth0)" || {
    cat "$LOG"
    die "DHCP offer not received"
}
case "$offer" in
    "offer 10.30.40."*) ;;
    *) die "unexpected DHCP result: $offer" ;;
esac
ok "$offer through kernel bridge"

log "routing and NAT"
nsenter -t "$pidA" -n ping -c 1 -W 2 192.0.2.2 >/dev/null || {
    cat "$LOG"
    die "NAT ping failed"
}
kill -TERM "$vpid"
wait "$vpid" 2>/dev/null || true
vpid=""
grep -Eq "snat=[1-9][0-9]*" "$LOG" || die "no SNAT counters"
ok "10.30.40.2 -> 192.0.2.2 with masquerade"

"$BIN/vnat" down -c "$CFG" || die "first vnat down failed"
log "kernel STP"
"$BIN/vnatd" -c "$CFG_STP" >"$LOG_STP" 2>&1 &
vpid=$!
for i in $(seq 1 100); do
    grep -q "started instance" "$LOG_STP" && break
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG_STP"
        die "vnatd (STP) exited"
    fi
    sleep 0.02
done
BR_STP="$(sed -n 's/.*kernel=\([^ ]*\).*/\1/p' "$LOG_STP" | head -1)"
[ -n "$BR_STP" ] || die "missing STP offload bridge"
grep -q "vlan_filtering 1" <<<"$(ip -d link show dev "$BR_STP")" ||
    die "STP bridge lost VLAN filtering"
ip -d link show dev "$BR_STP" | grep -q "stp_state 1" ||
    die "kernel STP is not enabled"
ok "stp_state=1 on $BR_STP"

log "rollback"
kill -TERM "$vpid"
wait "$vpid" 2>/dev/null || true
vpid=""
"$BIN/vnat" down -c "$CFG_STP" || die "vnat down failed"
for dev in "$BR" "$BR_STP" "$TRUNK"; do
    if ip link show dev "$dev" >/dev/null 2>&1; then
        die "$dev survived vnat down"
    fi
done
for dev in pa pb; do
    if ip -o link show dev "$dev" | grep -q "master "; then
        die "$dev kept its master after vnat down"
    fi
    ip -o link show dev "$dev" | grep -q "state DOWN" ||
        die "$dev was not restored to down"
done
[ "$("$BIN/vnat" journal -c "$CFG" 2>&1)" = "no journal" ] ||
    die "journal was not truncated"
ok "kernel bridge, veth, VLANs, and link state restored"

echo "--- vnatd ---"
cat "$LOG"
ok "test_offload"
