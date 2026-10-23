#!/usr/bin/env bash
# NAT matrix: SNAT/masquerade for UDP, ICMP echo and TCP, including source
# port preservation and collision allocation. DNAT/hairpin land in the next
# R3 increment.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VNAT_NAT_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNAT_NAT_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNAT_NAT_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vnat-nat.json"
LOG="$WORK/vnatd.log"
UDP_LOG="$WORK/udp.log"
HTTP_LOG="$WORK/http.log"

vpid=""
udp_pid=""
http_pid=""
pidA=""
pidB=""

cleanup() {
    [ -n "$http_pid" ] && kill "$http_pid" 2>/dev/null || true
    [ -n "$udp_pid" ] && kill "$udp_pid" 2>/dev/null || true
    [ -n "$vpid" ] && kill -TERM "$vpid" 2>/dev/null || true
    [ -n "$pidA" ] && kill "$pidA" 2>/dev/null || true
    [ -n "$pidB" ] && kill "$pidB" 2>/dev/null || true
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

for tool in ip unshare nsenter python3 ss ping timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat > "$CFG" <<'EOF'
{
  "version": 1,
  "instance": "nat-test",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "nat": { "masquerade": [ { "out": "wan0" } ] }
}
EOF

log "topology"
ip link set lo up
ip link add ra type veth peer name a0 || die "create veth pair ra/a0"
ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
ip link set ra up
ip link set rb up

start_host() {
    local peer="$1" addr="$2" gw="$3" marker="$4"
    unshare -n bash -c '
        peer=$1; addr=$2; gw=$3; marker=$4
        while ! ip link show "$peer" >/dev/null 2>&1; do sleep 0.02; done
        ip link set "$peer" name eth0
        ip link set eth0 up
        ip link set lo up
        ip addr add "$addr/24" dev eth0
        ip route add default via "$gw"
        touch "$marker"
        sleep 120
    ' _ "$peer" "$addr" "$gw" "$marker" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

pidA="$(start_host a0 10.0.1.2 10.0.1.1 "$WORK/a.ready")"
pidB="$(start_host b0 10.0.2.2 10.0.2.1 "$WORK/b.ready")"

ip link set a0 netns "$pidA" || die "move a0 into client"
ip link set b0 netns "$pidB" || die "move b0 into server"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "client did not configure"
[ -f "$WORK/b.ready" ] || die "server did not configure"

# A second address on the client exercises colliding source ports behind SNAT.
nsenter -t "$pidA" -n ip addr add 10.0.1.3/24 dev eth0 || die "add second client address"
ok "client 10.0.1.2/.3 and server 10.0.2.2"

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

log "udp echo server"
nsenter -t "$pidB" -n python3 -u -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.2.2", 9999))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(("peer=%s:%d" % (addr[0], addr[1])).encode(), addr)
' >"$UDP_LOG" 2>&1 &
udp_pid=$!

for i in $(seq 1 100); do
    nsenter -t "$pidB" -n ss -lun 2>/dev/null | grep -q ':9999' && break
    if ! kill -0 "$udp_pid" 2>/dev/null; then
        cat "$UDP_LOG"
        die "udp server exited"
    fi
    sleep 0.02
done
nsenter -t "$pidB" -n ss -lun 2>/dev/null | grep -q ':9999' || {
    cat "$UDP_LOG"
    die "udp server did not bind"
}

udp_probe() {
    local src="$1"
    nsenter -t "$pidA" -n python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 40000))
s.settimeout(3)
s.sendto(b"probe", ("10.0.2.2", 9999))
data, _ = s.recvfrom(2048)
print(data.decode())
' "$src"
}

log "snat udp"
peer1="$(udp_probe 10.0.1.2)" || {
    cat "$LOG"
    die "udp probe 1 failed"
}
[ "$peer1" = "peer=10.0.2.1:40000" ] || die "expected preserved source port, got $peer1"
ok "udp 10.0.1.2:40000 -> $peer1"

peer2="$(udp_probe 10.0.1.3)" || {
    cat "$LOG"
    die "udp probe 2 failed"
}
case "$peer2" in
    "peer=10.0.2.1:40000") die "colliding source port was not reallocated" ;;
    "peer=10.0.2.1:"*) ;;
    *) die "unexpected second peer $peer2" ;;
esac
ok "udp 10.0.1.3:40000 -> $peer2"

log "snat icmp"
ping_out="$(nsenter -t "$pidA" -n ping -c 3 -W 1 10.0.2.2 2>&1)" || {
    echo "$ping_out"
    cat "$LOG"
    die "ping failed"
}
echo "$ping_out" | grep -q "3 received" || {
    echo "$ping_out"
    die "ping loss through snat"
}
ok "icmp 10.0.1.2 -> 10.0.2.2 (3/3)"

log "snat tcp"
nsenter -t "$pidB" -n python3 -m http.server 8080 --bind 10.0.2.2 >"$HTTP_LOG" 2>&1 &
http_pid=$!

for i in $(seq 1 100); do
    nsenter -t "$pidB" -n ss -ltn 2>/dev/null | grep -q ':8080' && break
    if ! kill -0 "$http_pid" 2>/dev/null; then
        cat "$HTTP_LOG"
        die "http server exited"
    fi
    sleep 0.02
done

tcp_ok=0
for i in $(seq 1 10); do
    if timeout 5 nsenter -t "$pidA" -n bash -c '
        exec 3<>/dev/tcp/10.0.2.2/8080 || exit 1
        printf "GET / HTTP/1.0\r\n\r\n" >&3
        IFS= read -r -t 3 line <&3 || exit 1
        case "$line" in HTTP/1.*200*) exit 0;; *) exit 1;; esac
    ' 2>/dev/null; then
        tcp_ok=1
        break
    fi
    sleep 0.1
done
[ "$tcp_ok" = "1" ] || {
    cat "$HTTP_LOG"
    tail -20 "$LOG"
    die "tcp request through snat failed"
}
ok "tcp 10.0.1.2 -> 10.0.2.2:8080 (http 200)"

kill -0 "$vpid" 2>/dev/null || die "vnatd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -q "ct=[1-9]" "$LOG" || {
    cat "$LOG"
    die "conntrack did not record flows"
}
grep -q "snat=[1-9]" "$LOG" || {
    cat "$LOG"
    die "snat did not translate packets"
}
ok "conntrack and snat counters: $(grep 'stopping instance' "$LOG" | tail -1)"
