#!/usr/bin/env bash
# NAT matrix: SNAT/masquerade for UDP, ICMP echo and TCP, including source
# port preservation and collision allocation; DNAT/port forwarding and
# hairpin NAT.
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
export VNAT_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vnat-nat.json"
LOG="$WORK/vnatd.log"
UDP_LOG="$WORK/udp.log"
HTTP_LOG="$WORK/http.log"
HTTP2_LOG="$WORK/http2.log"

vpid=""
udp_pid=""
http_pid=""
http2_pid=""
pidA=""
pidB=""
pidC=""

cleanup() {
    [ -n "$http2_pid" ] && kill "$http2_pid" 2>/dev/null || true
    [ -n "$http_pid" ] && kill "$http_pid" 2>/dev/null || true
    [ -n "$udp_pid" ] && kill "$udp_pid" 2>/dev/null || true
    [ -n "$vpid" ] && kill -TERM "$vpid" 2>/dev/null || true
    [ -n "$pidA" ] && kill "$pidA" 2>/dev/null || true
    [ -n "$pidB" ] && kill "$pidB" 2>/dev/null || true
    [ -n "$pidC" ] && kill "$pidC" 2>/dev/null || true
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
    "lan": { "kind": "l2", "device": "lan0" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "nat": {
    "masquerade": [ { "out": "wan0" } ],
    "port_forward": [
      { "proto": "tcp", "ext_port": 8080, "to": "10.0.1.10:8000" },
      { "proto": "tcp", "ext_port": 8081, "to": "10.0.1.10:8000" },
      { "proto": "udp", "ext_port": 8082, "to": "10.0.1.10:8001" }
    ]
  },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
EOF

log "topology"
ip link set lo up
ip link add lan-br type veth peer name lan0 || die "create veth pair lan-br/lan0"
ip link add a-br type veth peer name a0 || die "create veth pair a-br/a0"
ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
ip link add c-br type veth peer name c0 || die "create veth pair c-br/c0"
ip link add br-lan type bridge || die "create lan bridge"
ip link set lan-br master br-lan || die "attach lan-br to lan bridge"
ip link set a-br master br-lan || die "attach a-br to lan bridge"
ip link set c-br master br-lan || die "attach c-br to lan bridge"
ip link set br-lan up
ip link set lan-br up
ip link set a-br up
ip link set c-br up
ip link set lan0 up
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
pidC="$(start_host c0 10.0.1.10 10.0.1.1 "$WORK/c.ready")"

ip link set a0 netns "$pidA" || die "move a0 into client"
ip link set b0 netns "$pidB" || die "move b0 into server"
ip link set c0 netns "$pidC" || die "move c0 into target"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && [ -f "$WORK/c.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "client did not configure"
[ -f "$WORK/b.ready" ] || die "server did not configure"
[ -f "$WORK/c.ready" ] || die "target did not configure"

# A second address on the client exercises colliding source ports behind SNAT.
nsenter -t "$pidA" -n ip addr add 10.0.1.3/24 dev eth0 || die "add second client address"
ok "client 10.0.1.2/.3, target 10.0.1.10 and server 10.0.2.2"

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

icmp_error_probe() {
    local ns_pid="$1" src="$2" dst="$3" dport="$4"
    nsenter -t "$ns_pid" -n python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.settimeout(4)
s.connect((sys.argv[2], int(sys.argv[3])))
s.send(b"probe")
try:
    s.recv(2048)
    print("no-error")
except ConnectionRefusedError:
    print("refused")
except OSError as e:
    print("error:%s" % e.errno)
' "$src" "$dst" "$dport"
}

log "snat icmp error"
snat_err="$(icmp_error_probe "$pidA" 10.0.1.2 10.0.2.2 9998)" || {
    cat "$LOG"
    die "snat icmp error probe failed"
}
case "$snat_err" in
    refused|error:111) ;;
    *) die "snat icmp error not translated: $snat_err" ;;
esac
ok "icmp error 10.0.2.2 -> 10.0.1.2 (snat reverse)"

log "dnat icmp error"
dnat_err="$(icmp_error_probe "$pidB" 10.0.2.2 10.0.2.1 8082)" || {
    cat "$LOG"
    die "dnat icmp error probe failed"
}
case "$dnat_err" in
    refused|error:111) ;;
    *) die "dnat icmp error not translated: $dnat_err" ;;
esac
ok "icmp error 10.0.1.10 -> 10.0.2.2 (dnat reverse)"

log "internal http server"
nsenter -t "$pidC" -n python3 -m http.server 8000 --bind 10.0.1.10 >"$HTTP2_LOG" 2>&1 &
http2_pid=$!

for i in $(seq 1 100); do
    nsenter -t "$pidC" -n ss -ltn 2>/dev/null | grep -q ':8000' && break
    if ! kill -0 "$http2_pid" 2>/dev/null; then
        cat "$HTTP2_LOG"
        die "internal http server exited"
    fi
    sleep 0.02
done
nsenter -t "$pidC" -n ss -ltn 2>/dev/null | grep -q ':8000' || {
    cat "$HTTP2_LOG"
    die "internal http server did not bind"
}

http_probe() {
    local ns_pid="$1" host="$2" port="$3"
    timeout 5 nsenter -t "$ns_pid" -n bash -c '
        exec 3<>/dev/tcp/"$1"/"$2" || exit 1
        printf "GET / HTTP/1.0\r\n\r\n" >&3
        IFS= read -r -t 3 line <&3 || exit 1
        case "$line" in HTTP/1.*200*) exit 0;; *) exit 1;; esac
    ' _ "$host" "$port" 2>/dev/null
}

log "dnat wan -> internal"
dnat_ok=0
for i in $(seq 1 10); do
    if http_probe "$pidB" 10.0.2.1 8081; then
        dnat_ok=1
        break
    fi
    sleep 0.1
done
[ "$dnat_ok" = "1" ] || {
    cat "$HTTP2_LOG"
    tail -20 "$LOG"
    die "dnat request failed"
}
ok "dnat 10.0.2.2 -> 10.0.2.1:8081 -> 10.0.1.10:8000 (http 200)"

log "hairpin dnat"
hairpin_ok=0
for i in $(seq 1 10); do
    if http_probe "$pidA" 10.0.2.1 8080; then
        hairpin_ok=1
        break
    fi
    sleep 0.1
done
[ "$hairpin_ok" = "1" ] || {
    cat "$HTTP2_LOG"
    tail -20 "$LOG"
    die "hairpin request failed"
}
ok "hairpin 10.0.1.2 -> 10.0.2.1:8080 -> 10.0.1.10:8000 (http 200)"

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
grep -q "dnat=[1-9]" "$LOG" || {
    cat "$LOG"
    die "dnat did not translate packets"
}
grep -q "icmp=[1-9]" "$LOG" || {
    cat "$LOG"
    die "icmp errors were not translated"
}
ok "conntrack, snat, dnat and icmp counters: $(grep 'stopping instance' "$LOG" | tail -1)"
