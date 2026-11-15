#!/bin/bash
set -eu
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
source <(sed 's#^\. /lib/functions/network.sh$#:#' "$ROOT_DIR/luci-app-passwall/root/usr/share/passwall/network.sh")
network_flush_cache() { :; }
__network_ifstatus() { printf -v "$1" '%s' 'lan wan wan6 proxy_guest'; }
network_get_device() {
 case "$2" in lan) printf -v "$1" br-lan ;; wan|wan6) printf -v "$1" eth0 ;; proxy_guest) return 1 ;; esac
}
network_get_physdev() {
 case "$2" in lan) printf -v "$1" br-lan ;; wan|wan6) printf -v "$1" eth0 ;; proxy_guest) printf -v "$1" br-proxy ;; esac
}
[ "$(passwall_proxy_interfaces eth0)" = $'wan\nwan6' ]
[ "$(passwall_proxy_interfaces br-lan)" = lan ]
[ "$(passwall_proxy_interfaces br-proxy)" = proxy_guest ]
[ -z "$(passwall_proxy_interfaces unknown)" ]
[ -z "$(passwall_proxy_interfaces '')" ]
echo 'Linux devices resolve to logical interfaces, including physical-device fallback when down'
