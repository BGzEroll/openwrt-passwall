#!/bin/bash
set -eu
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT_DIR/luci-app-passwall/root/usr/share/passwall/nftables.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
uci() { :; }
echolog() { :; }
source <(sed 's#^\. /lib/functions/network.sh$#:#' "$SCRIPT")
iproute_shunt=1
iproute_shunt_interface=lo
iproute_shunt_gw_v4=192.0.2.1
iproute_shunt_gw_v6=fe80::1

ADDRESS4= ADDRESS6= REJECT_GATEWAY=0
ip() {
 printf '%s\n' "$*" >> "$TEST_TMP/calls"
 if [ "${2:-}" = -o ]; then
  if [ "$1" = -4 ]; then printf '%s' "$ADDRESS4"; else printf '%s' "$ADDRESS6"; fi
 elif [ "${2:-}:${3:-}" = rule:show ]; then
  echo '32765: from all fwmark 0x1 lookup 100'
 elif [ "${3:-}:${4:-}:${5:-}" = replace:default:via ] && [ "$REJECT_GATEWAY" = 1 ]; then
  return 1
 fi
}
: > "$TEST_TMP/calls"
nft_routes
grep -q -- '-4 route replace unreachable default' "$TEST_TMP/calls"
grep -q -- '-6 route replace unreachable default' "$TEST_TMP/calls"
! grep -q 'replace default via' "$TEST_TMP/calls"
ADDRESS4=$'1: lo inet 192.0.2.2/24 scope global\n'
ADDRESS6=$'1: lo inet6 fe80::2/64 scope link tentative\n'
: > "$TEST_TMP/calls"
nft_routes
grep -q -- '-4 route replace default via 192.0.2.1' "$TEST_TMP/calls"
! grep -q -- '-6 route replace default via' "$TEST_TMP/calls"
ADDRESS6=$'1: lo inet6 fe80::2/64 scope link\n'
: > "$TEST_TMP/calls"
nft_routes
grep -q -- '-6 route replace default via fe80::1' "$TEST_TMP/calls"
REJECT_GATEWAY=1
if nft_routes; then echo 'Rejected gateway was treated as a missing address'; exit 1; fi

# The reload cache must observe a DAD-only readiness change as well.
lan_device=
RESOLVFILE="$TEST_TMP/resolv"
touch "$RESOLVFILE"
network_flush_cache() { :; }
network_get_device() { printf -v "$1" ''; }
ADDRESS6=$'1: lo inet6 fe80::2/64 scope link tentative\n'
nft_network_snapshot > "$TEST_TMP/tentative"
ADDRESS6=$'1: lo inet6 fe80::2/64 scope link dadfailed\n'
nft_network_snapshot > "$TEST_TMP/failed"
cmp "$TEST_TMP/tentative" "$TEST_TMP/failed"
ADDRESS6=$'1: lo inet6 fe80::2/64 scope link\n'
nft_network_snapshot > "$TEST_TMP/ready"
! cmp -s "$TEST_TMP/tentative" "$TEST_TMP/ready"
grep -q '^proxy_ready4=1$' "$TEST_TMP/ready"
grep -q '^proxy_ready6=0$' "$TEST_TMP/tentative"
grep -q '^proxy_ready6=1$' "$TEST_TMP/ready"
nft_network_snapshot > "$TEST_TMP/unchanged"
cmp "$TEST_TMP/ready" "$TEST_TMP/unchanged"
echo 'PBR waits for addresses/DAD, installs each ready family, and still rejects invalid gateways'
echo 'Network snapshots track per-family readiness and remain stable without a readiness change'
