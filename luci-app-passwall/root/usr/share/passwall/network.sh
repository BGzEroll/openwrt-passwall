#!/bin/sh

. /lib/functions/network.sh

# Resolve the configured Linux device to netifd logical interfaces. The physical
# device remains available when l3_device disappears during interface shutdown.
passwall_proxy_interfaces() {
	local interfaces interface l3_device physical_device
	[ -n "$1" ] || return 0
	network_flush_cache
	__network_ifstatus interfaces "" "[*].interface" || return 0
	for interface in $interfaces; do
		network_get_device l3_device "$interface" || l3_device=""
		network_get_physdev physical_device "$interface" || physical_device=""
		[ "$1" = "$l3_device" ] || [ "$1" = "$physical_device" ] || continue
		printf '%s\n' "$interface"
	done
}
