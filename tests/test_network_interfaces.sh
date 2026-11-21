#!/bin/bash
set -eu
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT
sed 's|/etc/init.d/passwall reload network|record_reload|' \
    "$ROOT_DIR/luci-app-passwall/root/etc/hotplug.d/iface/98-passwall" > "$TEST_TMP/hotplug"

record_reload() { printf '%s %s\n' "$INTERFACE" "$ACTION" >> "$TEST_TMP/events"; }
sleep() { :; }
event() (
 ACTION=$1 INTERFACE=$2
 source "$TEST_TMP/hotplug"
 wait
)

event ifup wan
event ifupdate wan6
event ifdown wan
event ifdown lan
event ifupdate localproxy
event ifup guest
event ifup ''
event iflink wan
printf '%s\n' 'wan ifup' 'wan6 ifupdate' 'wan ifdown' > "$TEST_TMP/expected"
cmp "$TEST_TMP/expected" "$TEST_TMP/events"
echo 'Hotplug reloads only for WAN and DHCPv6 uplink events'
