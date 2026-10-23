#!/usr/bin/env bash
# DNS forwarder netns test: client query -> vnatd cache/forwarder -> fake
# upstream, plus a second query served from cache.
set -euo pipefail

if [ "${VNAT_DNS_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNAT_DNS_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNAT_DNS_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
INSTANCE=dns-test
CONFIG=$WORK/config.json
LOG=$WORK/vnatd.log
UPSTREAM_LOG=$WORK/upstream.count
CLIENT_LOG=$WORK/client.log
SERVER_LOG=$WORK/upstream.log

cleanup() {
    set +e
    [ -n "${vnatd_pid:-}" ] && kill "$vnatd_pid" 2>/dev/null
    [ -n "${client_pid:-}" ] && kill "$client_pid" 2>/dev/null
    [ -n "${upstream_pid:-}" ] && kill "$upstream_pid" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

die() { echo "FAIL: $*" >&2; [ -f "$LOG" ] && cat "$LOG" >&2; exit 1; }

echo "==> build"
(cd "$ROOT" && "$ZIG" build)

echo "==> topology"
ip link set lo up
ip link add lan0 type veth peer name c0
ip link set lan0 up
ip addr add 10.30.0.1/24 dev lan0

unshare -n bash -c '
    touch "$1"
    while ! ip link show c0 >/dev/null 2>&1; do sleep 0.02; done
    ip link set c0 name eth0
    ip link set eth0 up
    ip addr add 10.30.0.100/24 dev eth0
    ip link set lo up
    touch "$2"
    sleep 120
' _ "$WORK/ns.ready" "$WORK/client.ready" </dev/null >"$CLIENT_LOG" 2>&1 &
client_pid=$!
for _ in $(seq 1 250); do [ -f "$WORK/ns.ready" ] && break; sleep 0.02; done
[ -f "$WORK/ns.ready" ] || die "client netns did not start"
ip link set c0 netns "$client_pid" || die "move c0 into client"
for _ in $(seq 1 250); do [ -f "$WORK/client.ready" ] && break; sleep 0.02; done
[ -f "$WORK/client.ready" ] || die "client interface did not come up"

cat >"$CONFIG" <<JSON
{
  "version": 1,
  "instance": "$INSTANCE",
  "ports": { "lan": { "kind": "l2", "device": "lan0" } },
  "interfaces": { "lan0": { "port": "lan", "address": "10.30.0.1/24" } },
  "dns": {
    "upstreams": ["127.0.0.1"],
    "listen": "10.30.0.1",
    "cache": true,
    "max_entries": 64
  },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
JSON

echo "==> fake upstream"
python3 -u - "$UPSTREAM_LOG" >"$SERVER_LOG" 2>&1 <<'PY' &
import socket, struct, sys

log = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
s.settimeout(30)
while True:
    try:
        query, peer = s.recvfrom(2048)
    except socket.timeout:
        break
    if len(query) < 17:
        continue
    qend = 12
    while qend < len(query) and query[qend] != 0:
        qend += 1 + query[qend]
    qend += 5
    if qend > len(query):
        continue
    response = bytearray(query[:qend])
    response[2:4] = struct.pack("!H", 0x8180)
    response[6:8] = struct.pack("!H", 1)
    response[8:10] = struct.pack("!H", 0)
    response[10:12] = struct.pack("!H", 0)
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    s.sendto(response, peer)
    with open(log, "a") as f:
        f.write("x\n")
PY
upstream_pid=$!

for _ in $(seq 1 100); do [ -s "$SERVER_LOG" ] && break; sleep 0.02; done

echo "==> vnatd"
"$ROOT/zig-out/bin/vnatd" -c "$CONFIG" >"$LOG" 2>&1 &
vnatd_pid=$!
for _ in $(seq 1 250); do
    grep -q "dns listening" "$LOG" 2>/dev/null && break
    kill -0 "$vnatd_pid" 2>/dev/null || die "vnatd exited during startup"
    sleep 0.02
done
grep -q "dns listening" "$LOG" || die "dns listener did not start"

echo "==> dns query"
nsenter -t "$client_pid" -n python3 -u - <<'PY' || die "dns query failed"
import socket, struct

def build(xid):
    q = struct.pack("!HHHHHH", xid, 0x0100, 1, 0, 0, 0)
    q += b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    return q

def parse(data, xid):
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    assert rid == xid, (rid, xid)
    assert flags & 0x8000 and flags & 0xf == 0, hex(flags)
    assert qd == 1 and an >= 1, (qd, an)
    pos = 12
    while data[pos] != 0:
        pos += 1 + data[pos]
    pos += 5
    assert data[pos] & 0xc0 == 0xc0, "expected compressed answer name"
    pos += 2
    typ, cls, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
    pos += 10
    assert typ == 1 and cls == 1 and rdlen == 4, (typ, cls, rdlen)
    return socket.inet_ntoa(data[pos:pos + 4]), ttl

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
for xid in (0x1111, 0x2222):
    s.sendto(build(xid), ("10.30.0.1", 53))
    data, _ = s.recvfrom(2048)
    ip, ttl = parse(data, xid)
    assert ip == "93.184.216.34", ip
    assert ttl > 0, ttl
print("ok: dns answer 93.184.216.34")
PY

echo "==> tcp"
nsenter -t "$client_pid" -n python3 -u - <<'PY' || die "dns tcp query failed"
import socket, struct

def build(xid, name):
    q = struct.pack("!HHHHHH", xid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return q

xid = 0x3333
payload = build(xid, "tcp.example.com")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("10.30.0.1", 53))
s.sendall(struct.pack("!H", len(payload)) + payload)
length = s.recv(2)
assert len(length) == 2
n = struct.unpack("!H", length)[0]
data = b""
while len(data) < n:
    chunk = s.recv(n - len(data))
    assert chunk
    data += chunk
s.close()
rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
assert rid == xid, (rid, xid)
assert flags & 0x8000 and flags & 0xf == 0, hex(flags)
assert qd == 1 and an >= 1, (qd, an)
print("ok: dns tcp answer")
PY

echo "==> cache"
count=$(wc -l <"$UPSTREAM_LOG")
[ "$count" -eq 2 ] || die "expected two upstream queries, saw $count"
echo "ok: second query served from cache"

kill -TERM "$vnatd_pid"
wait "$vnatd_pid" 2>/dev/null || true
grep -q "dns stopping queries=3 responses=3 hits=1" "$LOG" || {
    cat "$LOG" >&2
    die "dns counters mismatch"
}
echo "ok: dns counters"
