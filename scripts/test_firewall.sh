#!/usr/bin/env bash
# Firewall test: ordered first-match rules, default-drop forwarding, reject
# and explicit interface/port allows. Two isolated hosts talk through vrouterd.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VROUTER_FIREWALL_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VROUTER_FIREWALL_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VROUTER_FIREWALL_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VROUTER_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vrouter-firewall.json"
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

cat > "$CFG" <<'JSON'
{
  "version": 1,
  "instance": "firewall-test",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "firewall": {
    "default_in": "accept",
    "default_forward": "drop",
    "rules": [
      { "action": "drop", "proto": "icmp", "src": "10.0.1.2/32" },
      { "action": "accept", "proto": "icmp" },
      { "action": "accept", "proto": "tcp", "dport": 8080, "iif": "lan", "oif": "wan" },
      { "action": "reject", "proto": "tcp", "dport": 8081 }
    ]
  }
}
JSON

log "offline rule evaluation"
out="$("$BIN/vrouter" firewall test --proto tcp --src 10.0.1.2 --dst 10.0.2.2 --dport 8080 --iif lan --oif wan -c "$CFG")" || die "firewall test failed"
echo "$out" | grep -q "rule 3: accept" || die "expected rule 3 accept, got: $out"
out="$("$BIN/vrouter" firewall test --proto tcp --src 10.0.1.2 --dst 10.0.2.2 --dport 8082 --iif lan --oif wan -c "$CFG")" || die "firewall test failed"
echo "$out" | grep -q "default: drop" || die "expected default drop, got: $out"
out="$("$BIN/vrouter" firewall test --proto tcp --src 10.0.1.2 --dst 10.0.2.2 --dport 8081 --iif lan --oif wan -c "$CFG")" || die "firewall test failed"
echo "$out" | grep -q "rule 4: reject" || die "expected rule 4 reject, got: $out"
ok "ordered match, default and reject"

out="$("$BIN/vrouter" firewall list -c "$CFG")" || die "firewall list failed"
echo "$out" | grep -q "rate-limit: icmp=100/s arp=512/s dhcp=100/s" ||
    die "firewall list missing rate limits, got: $out"

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

log "ordered drop shadows later accept"
ping_out="$(nsenter -t "$pidA" -n ping -c 1 -W 1 10.0.2.2 2>&1)" && {
    echo "$ping_out"
    die "ping should have been dropped by the first rule"
}
ok "icmp from 10.0.1.2 dropped"

log "tcp accept"
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
    die "tcp accept rule failed"
}
ok "tcp dport 8080 accepted"

log "tcp reject"
reject_out="$(nsenter -t "$pidA" -n python3 -c '
import socket, time
start = time.monotonic()
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("10.0.2.2", 8081))
    print("connected")
except OSError as exc:
    print(exc.errno, round(time.monotonic() - start, 2))
' 2>&1)" || true
echo "$reject_out" | grep -q '^connected' && die "tcp 8081 unexpectedly connected"
elapsed="$(echo "$reject_out" | awk '{print $2}')"
case "$elapsed" in
    0.*) ;;
    *) die "tcp 8081 did not reject promptly: $reject_out" ;;
esac
ok "tcp dport 8081 rejected"

log "default drop"
drop_out="$(nsenter -t "$pidA" -n python3 -c '
import socket, time
start = time.monotonic()
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("10.0.2.2", 8082))
    print("connected")
except OSError:
    print(round(time.monotonic() - start, 2))
' 2>&1)" || true
echo "$drop_out" | grep -q '^connected' && die "tcp 8082 unexpectedly connected"
elapsed="$(echo "$drop_out" | awk '{print $1}')"
case "$elapsed" in
    2.*|3.*) ;;
    *) die "tcp 8082 was not silently dropped: $drop_out" ;;
esac
ok "tcp dport 8082 dropped by policy"

kill -0 "$vpid" 2>/dev/null || die "vrouterd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -q "fw-drop=" "$LOG" || {
    cat "$LOG"
    die "missing firewall counters"
}

log "runtime counters"
counter_out="$("$BIN/vrouter" firewall counters -c "$CFG")" || {
    cat "$LOG"
    die "firewall counters failed"
}
echo "$counter_out"
echo "$counter_out" | grep -Eq '^rule 3: [1-9][0-9]* packets$' ||
    die "rule 3 counters not exported: $counter_out"
echo "$counter_out" | grep -Eq '^rule 4: [1-9][0-9]* packets$' ||
    die "rule 4 counters not exported: $counter_out"
echo "$counter_out" | grep -Eq '^policy: dropped=[1-9]' ||
    die "firewall drop counters not exported: $counter_out"
ok "runtime firewall counters exported"

echo "--- vrouterd ---"
cat "$LOG"
ok "test_firewall"
