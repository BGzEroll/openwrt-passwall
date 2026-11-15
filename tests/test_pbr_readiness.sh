#!/bin/bash
set -eu
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT_DIR/luci-app-passwall/root/usr/share/passwall/nftables.sh"
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
uci() { :; }
echolog() { :; }
source <(sed 's#^\. /usr/share/passwall/network.sh$#:#' "$SCRIPT")
iproute_shunt=1
iproute_shunt_interface=lo
iproute_shunt_gw_v4=192.0.2.1
iproute_shunt_gw_v6=fe80::1
PROXY_IPV6=1
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
echo 'PBR waits for addresses/DAD, installs each ready family, and still rejects invalid gateways'
