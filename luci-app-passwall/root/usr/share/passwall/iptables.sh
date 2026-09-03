#!/bin/sh

# Client transparent proxying is nftables-only in this fork.  The two lookup
# commands remain because the independent passwall_server service still uses
# them while it keeps its historical fw3 fallback.

get_ipt_bin() {
	command -v iptables-legacy || command -v iptables
}

get_ip6t_bin() {
	command -v ip6tables-legacy || command -v ip6tables
}

case "$1" in
	get_ipt_bin) get_ipt_bin ;;
	get_ip6t_bin) get_ip6t_bin ;;
	start|stop|flush_ipset|flush_ipset_reload)
		echo "Passwall client transparent proxying only supports nftables." >&2
		exit 1
	;;
	*) ;;
esac
