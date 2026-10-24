#!/usr/bin/env bash
# R1 netns smoke test: AF_PACKET forwarding through two veth pairs, TUN/TAP
# creation, netlink enumeration, manager status and daemon hotplug. Runs
# inside a fresh network namespace; no host changes.
set -euo pipefail

if [[ "${VNAT_NETNS:-0}" != "1" ]]; then
  if ! command -v unshare >/dev/null 2>&1; then
    echo "test_netns: unshare is required" >&2
    exit 2
  fi
  if [[ "${EUID}" -eq 0 ]]; then
    exec unshare -n env VNAT_NETNS=1 bash "$0" "$@"
  else
    exec unshare -rn env VNAT_NETNS=1 bash "$0" "$@"
  fi
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "test_netns: iproute2 (ip) is required" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

ZIG="${ZIG:-zig}"
if ! command -v "$ZIG" >/dev/null 2>&1 && [[ ! -x "$ZIG" ]]; then
  echo "test_netns: zig not found; set ZIG=/path/to/zig" >&2
  exit 2
fi

echo "==> build"
"$ZIG" build --summary none

suffix="$$"
v0="vn0${suffix: -4}"
v1="vn1${suffix: -4}"
v2="vn2${suffix: -4}"
v3="vn3${suffix: -4}"

cfg="/tmp/vnat-netns-${suffix}.json"
status_log="/tmp/vnat-status-${suffix}.log"
daemon_log="/tmp/vnatd-${suffix}.log"
doctor_log="/tmp/vnat-doctor-${suffix}.log"
up_log="/tmp/vnat-up-${suffix}.log"
VNAT_RUN_DIR="${TMPDIR:-/tmp}/vnat-netns-run-${suffix}"
up_pid=""
export VNAT_RUN_DIR

cleanup() {
  if [[ -n "$up_pid" ]]; then
    kill -TERM "$up_pid" 2>/dev/null || true
  fi
  ip link del "$v0" 2>/dev/null || true
  ip link del "$v2" 2>/dev/null || true
  ip link del vnat-tun0 2>/dev/null || true
  ip link del vnat-tap0 2>/dev/null || true
  rm -rf "$cfg" "$status_log" "$daemon_log" "$doctor_log" "$up_log" "$VNAT_RUN_DIR"
}
trap cleanup EXIT

echo "==> topology: $v0 <-> $v1, $v2 <-> $v3"
ip link add "$v0" type veth peer name "$v1"
ip link add "$v2" type veth peer name "$v3"
for iface in "$v0" "$v1" "$v2" "$v3"; do
  ip link set "$iface" up
done

echo "==> l2 forwarding"
./zig-out/bin/vnat selftest l2 "$v0" "$v1" "$v3" "$v2"

echo "==> tun/tap creation"
./zig-out/bin/vnat selftest tun vnat-tun0
./zig-out/bin/vnat selftest tap vnat-tap0

echo "==> netlink dump"
./zig-out/bin/vnat port list | grep -q "$v0"

echo "==> manager status"
cat > "$cfg" <<CONFIG
{
  "version": 1,
  "instance": "netns",
  "ports": {
    "a": { "kind": "l2", "device": "$v1" },
    "b": { "kind": "l2", "device": "$v3" }
  }
}
CONFIG
./zig-out/bin/vnat validate "$cfg"
./zig-out/bin/vnat status -c "$cfg" | tee "$status_log"
grep -q "instance: netns" "$status_log"
grep -q "a " "$status_log"

echo "==> vnatd hotplug"
./zig-out/bin/vnatd -c "$cfg" 2>"$daemon_log" &
pid=$!
sleep 0.5
ip link set "$v2" down
ip link set "$v2" up
sleep 0.5
./zig-out/bin/vnat doctor -c "$cfg" >"$doctor_log"
grep -q "ok: daemon pid=" "$doctor_log"
./zig-out/bin/vnat up -c "$cfg" | grep -q "already running"
./zig-out/bin/vnat nat list -c "$cfg" | grep -q "^SNAT"
./zig-out/bin/vnat conntrack list -c "$cfg" | grep -q "^total="
if ./zig-out/bin/vnat down -c "$cfg" >/dev/null 2>&1; then
  echo "test_netns: vnat down ran while vnatd was live" >&2
  exit 1
fi
if ! kill -TERM "$pid" 2>/dev/null; then
  echo "test_netns: vnatd exited early" >&2
  cat "$daemon_log" >&2
  exit 1
fi
wait "$pid"
grep -q "started instance=netns" "$daemon_log"
grep -q "link add" "$daemon_log"
echo "ok: vnatd"

echo "==> vnat up daemon log"
./zig-out/bin/vnat up -c "$cfg" | tee "$up_log"
grep -q "log=$VNAT_RUN_DIR/vnatd.log" "$up_log"
grep -q "started instance=netns" "$VNAT_RUN_DIR/vnatd.log"
up_pid="$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$up_log" | head -n 1)"
test -n "$up_pid"
kill -TERM "$up_pid"
for _ in $(seq 1 100); do
  kill -0 "$up_pid" 2>/dev/null || break
  sleep 0.05
done
up_pid=""
echo "ok: vnat up"

echo "ok: test_netns"
