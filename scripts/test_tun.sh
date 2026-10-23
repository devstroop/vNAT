#!/usr/bin/env bash
# TUN ingress/egress test: a kernel peer sends IPv4 through a TUN owned by
# vnatd; vnatd forwards to a veth host and back. Covers bare-IP ingress, local
# ARP resolution, pending-packet flush, TCP checksum repair and TUN egress.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VNAT_TUN_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNAT_TUN_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNAT_TUN_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
for tool in ip unshare nsenter python3 timeout "$ZIG"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL: $tool is required" >&2
        exit 1
    }
done

WORK="$(mktemp -d)"
CFG="$WORK/tun.json"
BIN="$ROOT/zig-out/bin"
export VNAT_RUN_DIR="$WORK/run"

dev="tr$$"
peer="ta$$"
pid_a=""
pid_d=""
pid_http=""

cleanup() {
    kill "$pid_d" "$pid_http" "$pid_a" 2>/dev/null || true
    ip link del "$dev" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log() { printf '==> %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

log "topology"
ip link set lo up
unshare -n bash -c 'ip link set lo up; sleep 120' </dev/null >"$WORK/host.log" 2>&1 &
pid_a=$!
sleep 0.2

ip link add "$dev" type veth peer name "$peer" || die "create veth pair"
ip link set "$peer" netns "$pid_a"
ip link set "$dev" up
nsenter -t "$pid_a" -n ip link set "$peer" up
nsenter -t "$pid_a" -n ip addr add 10.0.1.2/24 dev "$peer"
nsenter -t "$pid_a" -n ip addr add 10.0.2.2/24 dev "$peer"
nsenter -t "$pid_a" -n ip route add 10.0.3.0/24 via 10.0.1.1 dev "$peer"

cat > "$CFG" <<'EOF'
{
  "version": 1,
  "instance": "tun-test",
  "ports": {
    "lan": { "kind": "l2", "device": "vnat-lan" },
    "vpn": { "kind": "l3", "device": "vnat0", "create": "tun", "mtu": 1400 }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "vpn0": { "port": "vpn", "address": "10.0.3.1/24" }
  },
  "routes": [
    { "dst": "10.0.2.0/24", "via": "10.0.1.2", "dev": "lan0" }
  ],
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
EOF

# The config uses a stable port name; rename the veth end before vnatd starts.
ip link set "$dev" name vnat-lan
dev="vnat-lan"

log "vnatd"
"$BIN/vnatd" -c "$CFG" >"$WORK/vnatd.log" 2>&1 &
pid_d=$!

for _ in $(seq 1 100); do
    ip link show vnat0 >/dev/null 2>&1 && break
    sleep 0.02
done
ip link show vnat0 >/dev/null 2>&1 || {
    cat "$WORK/vnatd.log"
    die "vnat0 was not created"
}

ip link set vnat0 up
ip addr add 10.0.3.2/24 dev vnat0
ip route add 10.0.2.0/24 via 10.0.3.1 dev vnat0

nsenter -t "$pid_a" -n python3 -m http.server 8080 --bind 10.0.2.2 \
    </dev/null >"$WORK/http.log" 2>&1 &
pid_http=$!
for _ in $(seq 1 100); do
    if nsenter -t "$pid_a" -n ss -ltn 2>/dev/null | grep -q '10.0.2.2:8080'; then
        break
    fi
    sleep 0.02
done

log "icmp over tun"
ping -c 3 -W 2 10.0.2.2 >"$WORK/ping.log" 2>&1 || {
    cat "$WORK/ping.log" "$WORK/vnatd.log"
    die "ping over tun failed"
}
grep -q '3 received' "$WORK/ping.log" || die "ping loss over tun"
grep -q 'ttl=63' "$WORK/ping.log" || die "tun path did not decrement ttl"
ok "ping over tun (ttl=63)"

log "tcp over tun"
status=""
for _ in $(seq 1 50); do
    status="$(timeout 2 bash -c '
        exec 3<>/dev/tcp/10.0.2.2/8080
        printf "GET / HTTP/1.0\r\nHost: 10.0.2.2\r\n\r\n" >&3
        IFS= read -r line <&3
        printf "%s" "$line"
    ' 2>/dev/null)" && break
    status=""
    sleep 0.05
done
if [ -z "$status" ]; then
    cat "$WORK/vnatd.log"
    die "tcp over tun timed out"
fi
case "$status" in
    *200*) ;;
    *)
        cat "$WORK/vnatd.log"
        die "unexpected http status: $status"
        ;;
esac
ok "tcp over tun ($status)"

log "stop"
kill -TERM "$pid_d"
for _ in $(seq 1 100); do
    kill -0 "$pid_d" 2>/dev/null || break
    sleep 0.02
done
wait "$pid_d" 2>/dev/null || true
pid_d=""
grep -q 'forwarded=' "$WORK/vnatd.log" || die "missing forwarding counters"
ok "vnatd stopped"

kill "$pid_http" 2>/dev/null || true
pid_http=""
ok "test_tun"
