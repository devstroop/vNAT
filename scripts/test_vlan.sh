#!/usr/bin/env bash
# VLAN bridge test: access <-> trunk forwarding, SVI addressing, and VLAN
# isolation with veth pairs and 802.1Q subinterfaces.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VROUTER_VLAN_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VROUTER_VLAN_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VROUTER_VLAN_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VROUTER_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vrouter-vlan.json"
LOG="$WORK/vrouterd.log"

vpid=""
pidA=""
pidB=""

cleanup() {
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

for tool in ip unshare nsenter; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat > "$CFG" <<'JSON'
{
  "version": 1,
  "instance": "vlan-test",
  "ports": {
    "access": { "kind": "l2", "device": "ra", "pvid": 10 },
    "trunk": { "kind": "l2", "device": "rb", "pvid": 20, "tagged": [10, 20] }
  },
  "bridges": {
    "br": { "ports": ["access", "trunk"], "vlan_aware": true }
  },
  "interfaces": {
    "lan0": { "bridge": "br", "address": "10.0.10.1/24", "vlan": 10 }
  },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
JSON

log "bridge inspection"
bridge_out="$("$BIN/vrouter" bridge list -c "$CFG")" || die "bridge list failed"
echo "$bridge_out"
echo "$bridge_out" | grep -Eq '^br +yes +off +none +2 +1$' ||
    die "unexpected bridge summary: $bridge_out"
echo "$bridge_out" | grep -Eq '^  port access +pvid=10 tagged=-$' ||
    die "unexpected access membership: $bridge_out"
echo "$bridge_out" | grep -Eq '^  port trunk +pvid=20 tagged=10,20$' ||
    die "unexpected trunk membership: $bridge_out"
echo "$bridge_out" | grep -Eq '^  svi lan0 +vlan=10 address=10.0.10.1/24$' ||
    die "unexpected SVI line: $bridge_out"
ok "bridge membership and SVI"

log "topology"
ip link set lo up
ip link add ra type veth peer name a0 || die "create veth pair ra/a0"
ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
ip link set ra up
ip link set rb up

start_host() {
    local peer="$1" addr10="$2" addr20="$3" marker="$4" mode="$5"
    unshare -n bash -c '
        peer=$1; addr10=$2; addr20=$3; marker=$4; mode=$5
        while ! ip link show "$peer" >/dev/null 2>&1; do sleep 0.02; done
        ip link set "$peer" name eth0
        ip link set eth0 up
        ip link set lo up
        if [ "$mode" = "access" ]; then
            ip addr add "$addr10/24" dev eth0
        else
            ip link add link eth0 name eth0.10 type vlan id 10
            ip link set eth0.10 up
            ip addr add "$addr10/24" dev eth0.10
        fi
        ip link add link eth0 name eth0.20 type vlan id 20
        ip link set eth0.20 up
        ip addr add "$addr20/24" dev eth0.20
        touch "$marker"
        sleep 120
    ' _ "$peer" "$addr10" "$addr20" "$marker" "$mode" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

pidA="$(start_host a0 10.0.10.2 10.0.20.2 "$WORK/a.ready" access)"
pidB="$(start_host b0 10.0.10.3 10.0.20.3 "$WORK/b.ready" trunk)"

ip link set a0 netns "$pidA" || die "move a0 into host A"
ip link set b0 netns "$pidB" || die "move b0 into host B"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "host A did not configure"
[ -f "$WORK/b.ready" ] || die "host B did not configure"
ok "hosts 10.0.10.2/24, 10.0.20.2/24 and peers configured"

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

log "access to trunk"
ping_out="$(nsenter -t "$pidA" -n ping -c 3 -W 1 10.0.10.3 2>&1)" || {
    echo "$ping_out"
    nsenter -t "$pidA" -n ip -s link show eth0 || true
    nsenter -t "$pidA" -n ip neigh show || true
    nsenter -t "$pidB" -n ip -s link show eth0.10 || true
    nsenter -t "$pidB" -n ip neigh show || true
    ip -s link show ra || true
    ip -s link show rb || true
    cat "$LOG"
    die "vlan 10 access -> trunk ping failed"
}
echo "$ping_out" | grep -q "3 received" || die "vlan 10 ping loss"
ok "vlan 10 access <-> trunk"

log "SVI"
ping_out="$(nsenter -t "$pidA" -n ping -c 1 -W 1 10.0.10.1 2>&1)" || {
    echo "$ping_out"
    cat "$LOG"
    die "SVI ping failed"
}
ok "vlan 10 SVI 10.0.10.1 reachable"

log "isolation"
if nsenter -t "$pidA" -n ping -c 1 -W 1 10.0.20.3 >/dev/null 2>&1; then
    die "tagged vlan 20 entered an access port"
fi
ok "vlan 20 tagged traffic dropped on access port"

kill -0 "$vpid" 2>/dev/null || die "vrouterd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -q "bridged=" "$LOG" || {
    cat "$LOG"
    die "missing bridge counters"
}

echo "--- vrouterd ---"
cat "$LOG"
ok "test_vlan"
