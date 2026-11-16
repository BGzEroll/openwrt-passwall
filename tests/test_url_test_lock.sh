#!/bin/sh
# Integration test: a dedicated OpenWrt router and an existing valid Xray node.
[ "${PASSWALL_TEST_ROUTER:-}" = 1 ] || { echo "Set PASSWALL_TEST_ROUTER=1 on the test router" >&2; exit 1; }
set -eu
node=${1:?Pass an existing Xray node ID}
work=$(mktemp -d /tmp/passwall-lock-probe.XXXXXX)
probe_pid=
finish() {
 [ -z "$probe_pid" ] || { kill "$probe_pid" 2>/dev/null || :; wait "$probe_pid" 2>/dev/null || :; }
 rm -rf "$work"
}
trap finish EXIT
/usr/share/passwall/test.sh url_test_node "$node" >"$work/output" 2>&1 &
probe_pid=$!
child=
for _ in $(seq 1 80); do
 for file in /tmp/passwall-urltest.*/pids; do
  [ -f "$file" ] || continue
  read -r pid < "$file" || continue
  [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" = /usr/bin/xray ] || continue
  child=$pid
  break
 done
 [ -z "$child" ] || break
 lua -e 'require("nixio").nanosleep(0, 50000000)'
done
[ -n "$child" ] || { echo 'FAIL: test Xray not observed'; exit 1; }
exec 6>/var/lock/passwall-url-test.lock
if flock -n 6; then echo 'FAIL: test wrapper lost its lock'; exit 1; fi
for descriptor in /proc/$child/fd/*; do
 target=$(readlink "$descriptor" 2>/dev/null || true)
 case "$target" in
  */passwall-url-test.lock) printf 'FAIL: test Xray inherited lock: %s -> %s\n' "$descriptor" "$target"; exit 1 ;;
 esac
done
wait "$probe_pid" || :
probe_pid=
flock -n 6 || { echo 'FAIL: test lock retained after completion'; exit 1; }
echo 'PASS: wrapper holds test lock, Xray has no lock descriptor, lock released afterward'
