#!/usr/bin/env bash
# IPv4 forwarding test: two isolated hosts talk through vrouterd across two L2
# ports. Exercises ARP, TTL decrement, ICMP echo and TCP checksum repair.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VROUTER_ROUTE_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VROUTER_ROUTE_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VROUTER_ROUTE_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VROUTER_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vrouter-route.json"
LOG="$WORK/vrouterd.log"
HTTP_LOG="$WORK/http.log"

vpid=""
hpid=""
pidA=""
pidB=""

cleanup() {
    [ -n "$hpid" ] && kill "$hpid" 2>/dev/null || true
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

for tool in ip unshare nsenter python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat > "$CFG" <<'EOF'
{
  "version": 1,
  "instance": "route-test",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
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

ip link set a0 netns "$pidA" || die "move a0 into host A"
ip link set b0 netns "$pidB" || die "move b0 into host B"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "host A did not configure"
[ -f "$WORK/b.ready" ] || die "host B did not configure"
ok "hosts 10.0.1.2/24 and 10.0.2.2/24 via vrouterd"

log "vrouterd"
"$BIN/vrouterd" -c "$CFG" >"$LOG" 2>&1 &
vpid=$!

for i in $(seq 1 100); do
    grep -q "started instance" "$LOG" && break
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG"
        die "vrouterd exited"
    fi
    sleep 0.02
done
grep -q "started instance" "$LOG" || {
    cat "$LOG"
    die "vrouterd did not start"
}

log "icmp"
nsenter -t "$pidA" -n ping -c 1 -W 1 10.0.2.2 >/dev/null 2>&1 || true
ping_out="$(nsenter -t "$pidA" -n ping -c 3 -W 1 10.0.2.2 2>&1)" || {
    echo "$ping_out"
    cat "$LOG"
    die "ping failed"
}
echo "$ping_out" | grep -q "3 received" || {
    echo "$ping_out"
    die "ping loss"
}
echo "$ping_out" | grep -q "ttl=63" || {
    echo "$ping_out"
    die "expected ttl=63 after forwarding"
}
ok "ping 10.0.1.2 -> 10.0.2.2 (ttl=63)"

log "tcp"
nsenter -t "$pidB" -n python3 -m http.server 8080 --bind 10.0.2.2 >"$HTTP_LOG" 2>&1 &
hpid=$!

for i in $(seq 1 100); do
    nsenter -t "$pidB" -n ss -ltn 2>/dev/null | grep -q ':8080' && break
    if ! kill -0 "$hpid" 2>/dev/null; then
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
    die "tcp request failed"
}
ok "tcp 10.0.1.2 -> 10.0.2.2:8080 (http 200)"

kill -0 "$vpid" 2>/dev/null || die "vrouterd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -q "forwarded=" "$LOG" || {
    cat "$LOG"
    die "missing forwarding counters"
}

echo "--- vrouterd ---"
cat "$LOG"
ok "test_route"
