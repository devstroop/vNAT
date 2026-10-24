#!/usr/bin/env bash
# DHCPv4 server: a fresh client broadcasts DISCOVER/REQUEST, receives an
# OFFER/ACK, configures the leased address and pings the router.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VROUTER_DHCP_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VROUTER_DHCP_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VROUTER_DHCP_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VROUTER_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vrouter-dhcp.json"
LOG="$WORK/vrouterd.log"

vpid=""
client_pid=""

cleanup() {
    [ -n "$vpid" ] && kill -TERM "$vpid" 2>/dev/null || true
    [ -n "$client_pid" ] && kill "$client_pid" 2>/dev/null || true
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

cat > "$CFG" <<EOF
{
  "version": 1,
  "instance": "dhcp-test",
  "lease_db": "$WORK/leases.json",
  "ports": {
    "lan": { "kind": "l2", "device": "lan0" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.20.0.1/24" }
  },
  "dhcp": [
    {
      "iface": "lan0",
      "pool": "10.20.0.100-10.20.0.120",
      "lease": "1h",
      "dns": "10.20.0.1"
    }
  ],
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
EOF

log "topology"
ip link set lo up
ip link add lan0 type veth peer name c0 || die "create veth pair lan0/c0"
ip link set lan0 up

unshare -n bash -c '
    touch "$1"
    while ! ip link show c0 >/dev/null 2>&1; do sleep 0.02; done
    ip link set c0 name eth0
    ip link set eth0 up
    ip link set lo up
    touch "$2"
    sleep 120
' _ "$WORK/ns.ready" "$WORK/client.ready" </dev/null >"$WORK/client.log" 2>&1 &
client_pid=$!

for i in $(seq 1 250); do
    [ -f "$WORK/ns.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/ns.ready" ] || die "client netns did not start"
ip link set c0 netns "$client_pid" || die "move c0 into client"

for i in $(seq 1 250); do
    [ -f "$WORK/client.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/client.ready" ] || die "client did not configure"

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

log "dhcp discover/request"
lease="$(nsenter -t "$client_pid" -n python3 -u -c '
import fcntl, socket, struct, sys

iface = sys.argv[1]
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mac = fcntl.ioctl(probe.fileno(), 0x8927, struct.pack("256s", iface.encode()[:15]))[18:24]
xid = 0x12345678
cookie = bytes([99, 130, 83, 99])

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def build(typ, requested=None, server_id=None):
    dhcp = bytearray(240)
    dhcp[0] = 1
    dhcp[1] = 1
    dhcp[2] = 6
    struct.pack_into("!I", dhcp, 4, xid)
    struct.pack_into("!H", dhcp, 10, 0x8000)
    dhcp[28:34] = mac
    dhcp[236:240] = cookie
    opts = bytearray([53, 1, typ])
    if requested:
        opts += bytes([50, 4]) + socket.inet_aton(requested)
    if server_id:
        opts += bytes([54, 4]) + socket.inet_aton(server_id)
    opts += bytes([255])
    dhcp = bytes(dhcp) + bytes(opts)

    udp = struct.pack("!HHHH", 68, 67, 8 + len(dhcp), 0) + dhcp
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(udp))
    struct.pack_into("!H", ip, 4, 1)
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = socket.inet_aton("0.0.0.0")
    ip[16:20] = socket.inet_aton("255.255.255.255")
    struct.pack_into("!H", ip, 10, checksum(bytes(ip)))
    return b"\xff" * 6 + mac + b"\x08\x00" + bytes(ip) + udp

def parse_options(p):
    i = 240
    opts = {}
    while i < len(p):
        code = p[i]
        i += 1
        if code == 0:
            continue
        if code == 255:
            break
        if i >= len(p):
            raise SystemExit("truncated option")
        length = p[i]
        i += 1
        opts[code] = p[i:i + length]
        i += length
    return opts

def receive():
    while True:
        frame = raw.recv(2048)
        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 17:
            continue
        udp = ip[ihl:]
        sport, dport, ulen, _ = struct.unpack("!HHHH", udp[:8])
        if sport != 67 or dport != 68:
            continue
        dhcp = udp[8:8 + ulen - 8]
        if len(dhcp) < 240 or dhcp[0] != 2 or dhcp[236:240] != cookie:
            continue
        return socket.inet_ntoa(dhcp[16:20]), parse_options(dhcp)

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind((iface, 0))
raw.settimeout(5)
raw.send(build(1))
yiaddr, opts = receive()
server = socket.inet_ntoa(opts[54])
raw.send(build(3, yiaddr, server))
yiaddr, opts = receive()
if opts.get(53) != bytes([5]):
    raise SystemExit("expected ACK")
print(yiaddr, socket.inet_ntoa(opts[54]))
' eth0)" || {
    cat "$LOG"
    die "dhcp exchange failed"
}

ip="${lease%% *}"
server="${lease##* }"
[ "$ip" = "10.20.0.100" ] || die "unexpected lease $ip"
[ "$server" = "10.20.0.1" ] || die "unexpected server $server"
ok "lease $ip from $server"

nsenter -t "$client_pid" -n ip addr add "$ip/24" dev eth0 || die "configure lease"
nsenter -t "$client_pid" -n ip route add default via 10.20.0.1 || die "add default route"
ping_out="$(nsenter -t "$client_pid" -n ping -c 2 -W 1 10.20.0.1 2>&1)" || {
    echo "$ping_out"
    cat "$LOG"
    die "ping router failed"
}
echo "$ping_out" | grep -q "2 received" || {
    echo "$ping_out"
    die "ping loss"
}
ok "client $ip pings router 10.20.0.1"

kill -0 "$vpid" 2>/dev/null || die "vrouterd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -q "dhcp=[1-9]" "$LOG" || {
    cat "$LOG"
    die "dhcp counters missing"
}
ok "dhcp counters: $(grep 'stopping instance' "$LOG" | tail -1)"

[ -f "$WORK/leases.json" ] || die "lease database was not written"
grep -q '"state":"bound"' "$WORK/leases.json" || die "lease database has no binding"
ok "lease database persisted"

log "restart"
: > "$LOG"
"$BIN/vrouterd" -c "$CFG" >"$LOG" 2>&1 &
vpid=$!
for i in $(seq 1 100); do
    grep -q "started instance" "$LOG" && break
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG"
        die "vrouterd restart exited"
    fi
    sleep 0.02
done
grep -q "dhcp leases restored=1" "$LOG" || {
    cat "$LOG"
    die "lease was not restored"
}
ok "lease restored after restart"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""
