#!/bin/sh
# Destructive integration test: dedicated OpenWrt test router only.
[ "${PASSWALL_TEST_ROUTER:-}" = 1 ] || { echo "Set PASSWALL_TEST_ROUTER=1 on the test router" >&2; exit 1; }
set -eu
work=$(mktemp -d /tmp/passwall-file-integration.XXXXXX)
cp /etc/config/passwall "$work/config"
for f in direct_host proxy_host gfwlist domains_excluded; do cp /usr/share/passwall/rules/$f "$work/$f"; done
restore() {
 cp "$work/config" /etc/config/passwall
 for f in direct_host proxy_host gfwlist domains_excluded; do
  cp "$work/$f" /usr/share/passwall/rules/$f
  cmp "$work/$f" /usr/share/passwall/rules/$f
 done
 /etc/init.d/passwall restart
 cmp "$work/config" /etc/config/passwall
 echo "PASS: original configuration and rule files restored"
 rm -rf "$work"
}
trap restore EXIT
pids() { ubus call service list '{"name":"passwall"}' | lua -e 'local j=require "luci.jsonc"; local d=j.parse(io.read("*a")); for _,i in pairs(d.passwall.instances) do print(i.command[3]:match("[^/]+$"),i.pid) end' | sort; }
uci set passwall.@global[0].dns_shunt=chinadns-ng
uci set passwall.@global[0].use_direct_list=1
uci set passwall.@global[0].use_proxy_list=1
uci set passwall.@global[0].use_gfw_list=1
uci commit passwall
/etc/init.d/passwall restart
: > /usr/share/passwall/rules/direct_host
/etc/init.d/passwall reload
pids > "$work/empty"
echo audit-direct.example > /usr/share/passwall/rules/direct_host
/etc/init.d/passwall reload rules
pids > "$work/filled"
[ "$(grep chinadns "$work/empty")" != "$(grep chinadns "$work/filled")" ]
rm /usr/share/passwall/rules/direct_host
/etc/init.d/passwall reload rules
pids > "$work/missing"
[ "$(grep chinadns "$work/filled")" != "$(grep chinadns "$work/missing")" ]
echo 'PASS: empty-to-filled and deleted list transitions reload ChinaDNS'
pids > "$work/before"
echo audit-file.example >> /usr/share/passwall/rules/proxy_host
/etc/init.d/passwall reload
sleep 1
pids > "$work/after"
cmp -s "$work/before" "$work/after" && { echo 'ERROR: DNS did not restart'; exit 1; }
[ "$(grep xray "$work/before")" = "$(grep xray "$work/after")" ]
echo 'PASS: file-only config reload replaces ChinaDNS and retains Xray'
/etc/init.d/passwall reload rules
pids > "$work/unchanged"
cmp "$work/after" "$work/unchanged"
echo 'PASS: unchanged files retain all PIDs'
mkdir "$work/staged"
cp /usr/share/passwall/rules/gfwlist "$work/staged/gfwlist"
echo audit-publish.example >> "$work/staged/gfwlist"
/etc/init.d/passwall update_rules "$work/staged"
sleep 1
pids > "$work/published"
[ "$(grep xray "$work/after")" = "$(grep xray "$work/published")" ]
[ "$(grep chinadns "$work/after")" != "$(grep chinadns "$work/published")" ]
echo 'PASS: downloaded GFW publication reloads ChinaDNS only'
# Force the replacement instance to reject its configuration.
echo invalid-audit-option >> /tmp/etc/passwall/acl/default/chinadns_ng.conf
nft list table inet passwall > "$work/nft.before"
cp /usr/share/passwall/rules/gfwlist "$work/gfw.before-failure"
echo audit-failed.example >> "$work/staged/gfwlist"
if /etc/init.d/passwall update_rules "$work/staged"; then echo 'ERROR: bad DNS config accepted'; exit 1; fi
cmp "$work/gfw.before-failure" /usr/share/passwall/rules/gfwlist
nft list table inet passwall > "$work/nft.after"
# Counters and expiry countdowns change while rules stay identical.
sed -E 's/packets [0-9]+ bytes [0-9]+/packets N bytes N/g; s/ expires [^, }]+//g' "$work/nft.before" > "$work/nft.old"
sed -E 's/packets [0-9]+ bytes [0-9]+/packets N bytes N/g; s/ expires [^, }]+//g' "$work/nft.after" > "$work/nft.new"
cmp "$work/nft.old" "$work/nft.new"
sleep 1
ubus call service list '{"name":"passwall"}' | lua -e 'local d=require("luci.jsonc").parse(io.read("*a")); for _,i in pairs(d.passwall.instances) do assert(i.running) end'
[ "$(grep xray "$work/published")" = "$(pids | grep xray)" ]
echo 'PASS: DNS replacement failure restores running old snapshot and retains Xray'
# Restore generator source before testing Xray dependencies.
sed -i '/invalid-audit-option/d' /tmp/etc/passwall/acl/default/chinadns_ng.conf
uci set passwall.@global_xray[0].sniffing_override_dest=1
uci commit passwall
/etc/init.d/passwall reload
pids > "$work/xray-before"
node=$(uci get passwall.@global[0].tcp_node)
uci set "passwall.$node.type=Unsupported"
uci commit passwall
echo audit-saved-config-error > /var/run/passwall/last_error
echo audit-excluded.example >> /usr/share/passwall/rules/domains_excluded
/etc/init.d/passwall reload rules
pids > "$work/xray-after"
[ "$(grep xray "$work/xray-before")" != "$(grep xray "$work/xray-after")" ]
grep -q audit-excluded.example /tmp/etc/passwall/acl/default/*.json
[ "$(cat /var/run/passwall/last_error)" = audit-saved-config-error ]
[ "$(uci -c /var/run/passwall/runtime/config get passwall.$node.type)" = Xray ]
echo 'PASS: file-only rules reload regenerates Xray using applied config and preserves rejected-config error'
/etc/init.d/passwall stop
/etc/init.d/passwall reload rules
[ ! -f /var/run/passwall/running ]
echo 'PASS: rules event does not start a stopped service'
