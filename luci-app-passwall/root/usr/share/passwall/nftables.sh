#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
NFTABLE_NAME="inet passwall"

# One mark namespace and one routing table are shared by packet marking,
# conntrack marking, policy routing and flow-offload exclusion.
PROXY_MARK="0x1"
BYPASS_MARK="0xff"
PROXY_ROUTE_TABLE="100"

NFTSET_DIRECT_MACS="passwall_direct_macs"
NFTSET_LANLIST="passwall_lanlist"
NFTSET_VPSLIST="passwall_vpslist"
NFTSET_SHUNTLIST="passwall_shuntlist"
NFTSET_GFW="passwall_gfwlist"
NFTSET_CHN="passwall_chnroute"
NFTSET_BLACKLIST="passwall_blacklist"
NFTSET_WHITELIST="passwall_whitelist"
NFTSET_BLOCKLIST="passwall_blocklist"

NFTSET_LANLIST6="passwall_lanlist6"
NFTSET_VPSLIST6="passwall_vpslist6"
NFTSET_SHUNTLIST6="passwall_shuntlist6"
NFTSET_GFW6="passwall_gfwlist6"
NFTSET_CHN6="passwall_chnroute6"
NFTSET_BLACKLIST6="passwall_blacklist6"
NFTSET_WHITELIST6="passwall_whitelist6"
NFTSET_BLOCKLIST6="passwall_blocklist6"

. /lib/functions/network.sh

FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"

factor() {
	if [ -z "$1" ] || [ -z "$2" ] || [ "$1" = "1:65535" ]; then
		echo ""
	else
		echo "$2 {$(echo "$1" | sed 's/:/-/g; s/,/, /g')}"
	fi
}

create_chain() {
	nft "add chain $NFTABLE_NAME $1" 2>/dev/null
	nft "flush chain $NFTABLE_NAME $1"
}

gen_nft_tables() {
	local table_file="$TMP_PATH/PSW_TABLE.nft"
	cat > "$table_file" <<-EOF
	table $NFTABLE_NAME {
		chain dstnat {
			type nat hook prerouting priority dstnat - 1; policy accept;
		}
		chain mangle_prerouting {
			type filter hook prerouting priority mangle - 1; policy accept;
		}
		chain mangle_output {
			type route hook output priority mangle - 1; policy accept;
		}
		chain nat_output {
			type nat hook output priority -1; policy accept;
		}
		chain hwnat_pass {
			type filter hook forward priority filter - 1; policy accept;
		}
	}
	EOF
	nft delete table $NFTABLE_NAME 2>/dev/null
	nft -f "$table_file"
	rm -f "$table_file"
}

insert_nftset() {
	local nftset_name="$1" timeout_argument="$2"
	shift 2
	local default_timeout="3650d" elements
	[ -n "${1:-}" ] || return 0
	if [ "$timeout_argument" = "-1" ]; then
		elements=$(echo -e "$*" | sed 's/[[:space:]]\+/, /g')
	elif [ "$timeout_argument" = "0" ]; then
		elements=$(echo -e "$*" | sed "s/[[:space:]]\+/ timeout $default_timeout, /g; s/$/ timeout $default_timeout/")
	else
		elements=$(echo -e "$*" | sed "s/[[:space:]]\+/ timeout $timeout_argument, /g; s/$/ timeout $timeout_argument/")
	fi
	mkdir -p "$TMP_PATH2/nftset"
	cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
	define $nftset_name = {$elements}
	add element $NFTABLE_NAME $nftset_name \$$nftset_name
	EOF
	nft -f "$TMP_PATH2/nftset/$nftset_name"
	rm -rf "$TMP_PATH2/nftset"
}

gen_nftset() {
	local nftset_name="$1" ip_type="$2" set_timeout="$3" element_timeout="$4"
	shift 4
	if ! nft "list set $NFTABLE_NAME $nftset_name" >/dev/null 2>&1; then
		if [ "$set_timeout" = "0" ]; then
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set $NFTABLE_NAME $nftset_name { type $ip_type; flags interval, timeout; timeout $set_timeout; gc-interval $set_timeout; auto-merge; }"
		fi
	fi
	if [ -n "${1:-}" ]; then
		insert_nftset "$nftset_name" "$element_timeout" "$@"
	fi
	return 0
}

gen_lanlist() {
	grep -v '^#' "$RULES_PATH/lanlist_ipv4" | sed '/^$/d'
}

gen_lanlist_6() {
	grep -v '^#' "$RULES_PATH/lanlist_ipv6" | sed '/^$/d'
}

load_rule_set() {
	local set_name="$1" ip_type="$2" rule_file="$3"
	local cache_file="$RULES_PATH/$rule_file.nft"
	if [ -s "$cache_file" ] && [ "$(awk 'END { print NR }' "$cache_file")" -ge 8 ]; then
		if nft -f "$cache_file"; then
			return 0
		fi
	fi
	gen_nftset "$set_name" "$ip_type" 2d 0 $(grep -v '^#' "$RULES_PATH/$rule_file" | sed '/^$/d')
}

get_wan_ip() {
	local net_if net_addr
	network_flush_cache
	network_find_wan net_if
	network_get_ipaddr net_addr "$net_if"
	echo "$net_addr"
}

get_wan6_ip() {
	local net_if net_addr
	network_flush_cache
	network_find_wan6 net_if
	network_get_ipaddr6 net_addr "$net_if"
	echo "$net_addr"
}

add_lan_network() {
	local logical_if="$1" subnets4 subnets6 device
	[ -n "$logical_if" ] || return 0
	network_get_subnets subnets4 "$logical_if"
	network_get_subnets6 subnets6 "$logical_if"
	[ -n "$subnets4" ] && insert_nftset "$NFTSET_LANLIST" -1 $subnets4
	[ -n "$subnets6" ] && insert_nftset "$NFTSET_LANLIST6" -1 $subnets6

	# network_get_subnets* is preferred; the device fallback covers unusual
	# netifd state while retaining all bridge/VLAN addresses.
	if [ -z "$subnets4$subnets6" ]; then
		network_get_device device "$logical_if"
		[ -n "$device" ] || return 0
		subnets4=$(ip -o -4 address show dev "$device" 2>/dev/null | awk '{print $4}')
		subnets6=$(ip -o -6 address show dev "$device" scope global 2>/dev/null | awk '{print $4}')
		[ -n "$subnets4" ] && insert_nftset "$NFTSET_LANLIST" -1 $subnets4
		[ -n "$subnets6" ] && insert_nftset "$NFTSET_LANLIST6" -1 $subnets6
	fi
}

collect_lan_zone() {
	local section="$1" name networks
	config_get name "$section" name
	[ "$name" = "lan" ] || return 0
	config_get networks "$section" network
	local logical_if
	for logical_if in $networks; do
		add_lan_network "$logical_if"
	done
}

setup_sets() {
	gen_nftset "$NFTSET_VPSLIST" ipv4_addr 0 0
	gen_nftset "$NFTSET_GFW" ipv4_addr 2d 0
	gen_nftset "$NFTSET_LANLIST" ipv4_addr 0 -1 $(gen_lanlist)
	load_rule_set "$NFTSET_CHN" ipv4_addr chnroute
	gen_nftset "$NFTSET_BLACKLIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/proxy_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_WHITELIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/direct_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_BLOCKLIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/block_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_SHUNTLIST" ipv4_addr 0 0

	gen_nftset "$NFTSET_VPSLIST6" ipv6_addr 0 0
	gen_nftset "$NFTSET_GFW6" ipv6_addr 2d 0
	gen_nftset "$NFTSET_LANLIST6" ipv6_addr 0 -1 $(gen_lanlist_6)
	load_rule_set "$NFTSET_CHN6" ipv6_addr chnroute6
	gen_nftset "$NFTSET_BLACKLIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/proxy_ip" | grep -E ':')
	gen_nftset "$NFTSET_WHITELIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/direct_ip" | grep -E ':')
	gen_nftset "$NFTSET_BLOCKLIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/block_ip" | grep -E ':')
	gen_nftset "$NFTSET_SHUNTLIST6" ipv6_addr 0 0

	nft "add set $NFTABLE_NAME $NFTSET_DIRECT_MACS { type ether_addr; }"

	local shunt_id shunt_ids
	shunt_ids=$(uci show "$CONFIG" | grep '=shunt_rules' | cut -d. -f2 | cut -d= -f1)
	for shunt_id in $shunt_ids; do
		insert_nftset "$NFTSET_SHUNTLIST" -1 $(config_n_get "$shunt_id" ip_list | tr -s '\r\n' '\n' | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
		insert_nftset "$NFTSET_SHUNTLIST6" -1 $(config_n_get "$shunt_id" ip_list | tr -s '\r\n' '\n' | grep -E ':')
	done

	network_flush_cache
	config_load firewall
	config_foreach collect_lan_zone zone
	# Some minimal configurations have no explicitly named lan firewall zone.
	add_lan_network lan

	local wan_ip wan6_ip
	wan_ip=$(get_wan_ip)
	wan6_ip=$(get_wan6_ip)
	[ -n "$wan_ip" ] && insert_nftset "$NFTSET_LANLIST" -1 "$wan_ip"
	[ -n "$wan6_ip" ] && insert_nftset "$NFTSET_LANLIST6" -1 "$wan6_ip"

	local isp
	for isp in $ISP_DNS; do
		insert_nftset "$NFTSET_WHITELIST" 0 "$isp"
	done
	for isp in $ISP_DNS6; do
		insert_nftset "$NFTSET_WHITELIST6" 0 "$isp"
	done
}

filter_haproxy() {
	local item ip
	for item in $haproxy_items; do
		ip=$(get_host_ip ipv4 "$(echo "$item" | awk -F: '{print $1}')" 1)
		[ -n "$ip" ] && insert_nftset "$NFTSET_VPSLIST" -1 "$ip"
	done
}

filter_vps_addr() {
	local server_host vps_ip4 vps_ip6
	for server_host in "$@"; do
		[ -n "$server_host" ] || continue
		vps_ip4=$(get_host_ip ipv4 "$server_host")
		vps_ip6=$(get_host_ip ipv6 "$server_host")
		[ -n "$vps_ip4" ] && insert_nftset "$NFTSET_VPSLIST" -1 "$vps_ip4"
		[ -n "$vps_ip6" ] && insert_nftset "$NFTSET_VPSLIST6" -1 "$vps_ip6"
	done
	return 0
}

filter_vpsip() {
	insert_nftset "$NFTSET_VPSLIST" -1 $(uci show "$CONFIG" | grep '.address=' | cut -d "'" -f2 | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$')
	insert_nftset "$NFTSET_VPSLIST6" -1 $(uci show "$CONFIG" | grep '.address=' | cut -d "'" -f2 | grep -E ':')
}

setup_proxy_actions() {
	create_chain PSW_MARK
	nft "add rule $NFTABLE_NAME PSW_MARK counter meta mark set $PROXY_MARK ct mark set mark return"

	local chain family port
	for chain in PSW_PROXY_TCP4 PSW_PROXY_UDP4 PSW_PROXY_TCP6 PSW_PROXY_UDP6; do
		create_chain "$chain"
	done

	if [ "$iproute_shunt" = "1" ]; then
		for chain in PSW_PROXY_TCP4 PSW_PROXY_UDP4 PSW_PROXY_TCP6 PSW_PROXY_UDP6; do
			nft "add rule $NFTABLE_NAME $chain goto PSW_MARK"
		done
	else
		nft "add rule $NFTABLE_NAME PSW_PROXY_TCP4 jump PSW_MARK"
		nft "add rule $NFTABLE_NAME PSW_PROXY_TCP4 meta l4proto tcp counter tproxy ip to :$TCP_REDIR_PORT return"
		nft "add rule $NFTABLE_NAME PSW_PROXY_UDP4 jump PSW_MARK"
		nft "add rule $NFTABLE_NAME PSW_PROXY_UDP4 meta l4proto udp counter tproxy ip to :$UDP_REDIR_PORT return"
		nft "add rule $NFTABLE_NAME PSW_PROXY_TCP6 jump PSW_MARK"
		nft "add rule $NFTABLE_NAME PSW_PROXY_TCP6 meta l4proto tcp counter tproxy ip6 to :$TCP_REDIR_PORT return"
		nft "add rule $NFTABLE_NAME PSW_PROXY_UDP6 jump PSW_MARK"
		nft "add rule $NFTABLE_NAME PSW_PROXY_UDP6 meta l4proto udp counter tproxy ip6 to :$UDP_REDIR_PORT return"
	fi

	create_chain PSW_ROUTE_PROXY
	nft "add rule $NFTABLE_NAME PSW_ROUTE_PROXY goto PSW_MARK"
}

add_global_policy_rules() {
	local chain="$1" family="$2"
	local daddr lan_set vps_set direct_set block_set shunt_set proxy_set gfw_set chn_set
	if [ "$family" = "4" ]; then
		daddr="ip daddr"
		lan_set="$NFTSET_LANLIST"; vps_set="$NFTSET_VPSLIST"
		direct_set="$NFTSET_WHITELIST"; block_set="$NFTSET_BLOCKLIST"
		shunt_set="$NFTSET_SHUNTLIST"; proxy_set="$NFTSET_BLACKLIST"
		gfw_set="$NFTSET_GFW"; chn_set="$NFTSET_CHN"
	else
		daddr="ip6 daddr"
		lan_set="$NFTSET_LANLIST6"; vps_set="$NFTSET_VPSLIST6"
		direct_set="$NFTSET_WHITELIST6"; block_set="$NFTSET_BLOCKLIST6"
		shunt_set="$NFTSET_SHUNTLIST6"; proxy_set="$NFTSET_BLACKLIST6"
		gfw_set="$NFTSET_GFW6"; chn_set="$NFTSET_CHN6"
	fi

	nft "add rule $NFTABLE_NAME $chain $daddr @$lan_set counter meta mark set $BYPASS_MARK return"
	nft "add rule $NFTABLE_NAME $chain $daddr @$vps_set counter meta mark set $BYPASS_MARK return"
	[ "$USE_DIRECT_LIST" = "1" ] && nft "add rule $NFTABLE_NAME $chain $daddr @$direct_set counter meta mark set $BYPASS_MARK return"
	[ "$USE_BLOCK_LIST" = "1" ] && nft "add rule $NFTABLE_NAME $chain $daddr @$block_set counter drop"
	[ "$family" = "4" ] && nft "add rule $NFTABLE_NAME $chain $daddr $FAKE_IP counter goto PSW_MARK"
	nft "add rule $NFTABLE_NAME $chain $daddr @$shunt_set counter goto PSW_MARK"
	[ "$USE_PROXY_LIST" = "1" ] && nft "add rule $NFTABLE_NAME $chain $daddr @$proxy_set counter goto PSW_MARK"
	[ "$USE_GFW_LIST" = "1" ] && nft "add rule $NFTABLE_NAME $chain $daddr @$gfw_set counter goto PSW_MARK"
	case "$CHN_LIST" in
		direct) nft "add rule $NFTABLE_NAME $chain $daddr @$chn_set counter meta mark set $BYPASS_MARK return" ;;
		proxy) nft "add rule $NFTABLE_NAME $chain $daddr @$chn_set counter goto PSW_MARK" ;;
	esac
	nft "add rule $NFTABLE_NAME $chain return"
}

setup_global_policy() {
	create_chain PSW_POLICY_V4
	create_chain PSW_POLICY_V6
	add_global_policy_rules PSW_POLICY_V4 4
	add_global_policy_rules PSW_POLICY_V6 6
}

protocol_available() {
	case "$1" in
		tcp)
			[ "$TCP_NODE" != "nil" ] && [ "$(config_get_type "$TCP_NODE" nil)" != "nil" ]
			;;
		udp)
			if [ "$TCP_UDP" = "1" ]; then
				[ "$TCP_NODE" != "nil" ] && [ "$(config_get_type "$TCP_NODE" nil)" != "nil" ]
			else
				[ "$UDP_NODE" != "nil" ] && [ "$(config_get_type "$UDP_NODE" nil)" != "nil" ]
			fi
			;;
	esac
}

protocol_default_mode() {
	case "$1" in
		tcp) echo "$TCP_PROXY_MODE" ;;
		udp) echo "$UDP_PROXY_MODE" ;;
	esac
}

policy_chain_for_family() {
	[ "$1" = "4" ] && echo PSW_POLICY_V4 || echo PSW_POLICY_V6
}

proxy_chain_for() {
	local proto_upper
	proto_upper=$(echo "$2" | tr 'a-z' 'A-Z')
	echo "PSW_PROXY_${proto_upper}$1"
}

add_policy_port_result() {
	local chain="$1" family="$2" proto="$3" ports="$4" result="$5" default_mode="$6" output_path="$7"
	[ -n "$ports" ] && [ "$ports" != "disable" ] || return 0
	protocol_available "$proto" || return 0

	local family_match policy_chain action_chain match
	[ "$family" = "4" ] && family_match="meta nfproto ipv4" || family_match="meta nfproto ipv6"
	policy_chain=$(policy_chain_for_family "$family")
	if [ "$output_path" = "1" ]; then
		action_chain=PSW_ROUTE_PROXY
	else
		action_chain=$(proxy_chain_for "$family" "$proto")
	fi
	match="$family_match meta l4proto $proto $(factor "$ports" "$proto dport")"

	nft "add rule $NFTABLE_NAME $chain $match jump $policy_chain"
	if [ "$result" = "drop" ]; then
		nft "add rule $NFTABLE_NAME $chain $match meta mark $PROXY_MARK counter drop"
		nft "add rule $NFTABLE_NAME $chain $match meta mark $BYPASS_MARK counter return"
		[ "$default_mode" = "proxy" ] && nft "add rule $NFTABLE_NAME $chain $match counter drop"
	else
		nft "add rule $NFTABLE_NAME $chain $match meta mark $PROXY_MARK counter goto $action_chain"
		nft "add rule $NFTABLE_NAME $chain $match meta mark $BYPASS_MARK counter return"
		[ "$default_mode" = "proxy" ] && nft "add rule $NFTABLE_NAME $chain $match counter goto $action_chain"
	fi
	nft "add rule $NFTABLE_NAME $chain $match counter return"
}

add_port_policy() {
	local chain="$1" tcp_bypass="$2" udp_bypass="$3" tcp_drop="$4" udp_drop="$5" tcp_proxy="$6" udp_proxy="$7" output_path="${8:-0}"
	local family family_match
	for family in 4 6; do
		[ "$family" = "4" ] && family_match="meta nfproto ipv4" || family_match="meta nfproto ipv6"
		[ "$tcp_bypass" != "disable" ] && nft "add rule $NFTABLE_NAME $chain $family_match meta l4proto tcp $(factor "$tcp_bypass" 'tcp dport') counter return"
		[ "$udp_bypass" != "disable" ] && nft "add rule $NFTABLE_NAME $chain $family_match meta l4proto udp $(factor "$udp_bypass" 'udp dport') counter return"
		add_policy_port_result "$chain" "$family" tcp "$tcp_drop" drop "$(protocol_default_mode tcp)" "$output_path"
		add_policy_port_result "$chain" "$family" udp "$udp_drop" drop "$(protocol_default_mode udp)" "$output_path"
		add_policy_port_result "$chain" "$family" tcp "$tcp_proxy" proxy "$(protocol_default_mode tcp)" "$output_path"
		add_policy_port_result "$chain" "$family" udp "$udp_proxy" proxy "$(protocol_default_mode udp)" "$output_path"
	done
	nft "add rule $NFTABLE_NAME $chain counter return"
}

valid_macs() {
	local item
	for item in $1; do
		if echo "$item" | grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
			echo "$item" | tr 'a-f' 'A-F'
		fi
	done
}

mac_match() {
	local macs
	macs=$(valid_macs "$1" | paste -sd, - | sed 's/,/, /g')
	[ -n "$macs" ] && echo "ether saddr { $macs }"
}

acl_ids() {
	uci show "$CONFIG" | grep '=acl_rule' | cut -d. -f2 | cut -d= -f1
}

acl_value() {
	local sid="$1" key="$2" fallback="$3" value
	value=$(config_n_get "$sid" "$key" "$fallback")
	[ "$value" = "default" ] && value=$(config_t_get global_forwarding "$key" "$fallback")
	echo "$value"
}

setup_acl() {
	[ "$ENABLED_ACLS" = "1" ] || return 0
	local sid sources direct remarks macs mac_csv chain

	# Aggregate every Direct ACL first. This gives Direct priority even if the
	# same MAC also appears in an earlier normal ACL.
	for sid in $(acl_ids); do
		[ "$(config_n_get "$sid" enabled 0)" = "1" ] || continue
		direct=$(config_n_get "$sid" direct 0)
		[ "$direct" = "1" ] || continue
		sources=$(config_n_get "$sid" sources)
		mac_csv=$(valid_macs "$sources" | paste -sd, - | sed 's/,/, /g')
		[ -n "$mac_csv" ] && nft "add element $NFTABLE_NAME $NFTSET_DIRECT_MACS { $mac_csv }" 2>/dev/null
	done

	for sid in $(acl_ids); do
		[ "$(config_n_get "$sid" enabled 0)" = "1" ] || continue
		[ "$(config_n_get "$sid" direct 0)" = "1" ] && continue
		sources=$(config_n_get "$sid" sources)
		macs=$(mac_match "$sources")
		[ -n "$macs" ] || {
			echolog "  - ACL[$sid] 未包含有效 MAC，旧 IP/CIDR/range/ipset source 已忽略。"
			continue
		}
		chain="PSW_ACL_$(echo "$sid" | tr -cd 'A-Za-z0-9_')"
		create_chain "$chain"
		add_port_policy "$chain" \
			"$(acl_value "$sid" tcp_no_redir_ports disable)" \
			"$(acl_value "$sid" udp_no_redir_ports disable)" \
			"$(acl_value "$sid" tcp_proxy_drop_ports disable)" \
			"$(acl_value "$sid" udp_proxy_drop_ports disable)" \
			"$(acl_value "$sid" tcp_redir_ports disable)" \
			"$(acl_value "$sid" udp_redir_ports disable)"
		nft "add rule $NFTABLE_NAME PSW_MANGLE $macs counter goto $chain"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 $macs counter goto $chain"
		remarks=$(config_n_get "$sid" remarks "$sid")
		echolog "  - ACL[$remarks]：MAC + 独立端口，目的策略/节点/DNS复用全局。"
	done
}

setup_client_chains() {
	create_chain PSW_DIVERT
	nft "add rule $NFTABLE_NAME PSW_DIVERT meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK ct mark set mark counter accept"

	create_chain PSW_MANGLE
	create_chain PSW_MANGLE_V6
	nft "add rule $NFTABLE_NAME PSW_MANGLE ether saddr @$NFTSET_DIRECT_MACS counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 ether saddr @$NFTSET_DIRECT_MACS counter return"

	# DNS hijack is a global NAT decision. Let client DNS leave mangle before
	# any ACL/default TPROXY rule so dstnat can redirect it to the router's DNS.
	if [ "$(config_t_get global dns_redirect 0)" = "1" ]; then
		nft "add rule $NFTABLE_NAME PSW_MANGLE meta l4proto { tcp, udp } th dport 53 counter return"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 meta l4proto { tcp, udp } th dport 53 counter return"
	fi

	# Locally generated marked packets return through lo only with local TPROXY.
	# PBR mode routes them directly to the configured external gateway instead.
	if [ "$iproute_shunt" != "1" ]; then
		nft "add rule $NFTABLE_NAME PSW_MANGLE iif lo meta mark $PROXY_MARK meta l4proto tcp counter goto PSW_PROXY_TCP4"
		nft "add rule $NFTABLE_NAME PSW_MANGLE iif lo meta mark $PROXY_MARK meta l4proto udp counter goto PSW_PROXY_UDP4"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo meta mark $PROXY_MARK meta l4proto tcp counter goto PSW_PROXY_TCP6"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo meta mark $PROXY_MARK meta l4proto udp counter goto PSW_PROXY_UDP6"
	fi
	nft "add rule $NFTABLE_NAME PSW_MANGLE iif lo counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo counter return"

	setup_acl

	create_chain PSW_DEFAULT_PORTS
	add_port_policy PSW_DEFAULT_PORTS "$TCP_NO_REDIR_PORTS" "$UDP_NO_REDIR_PORTS" \
		"$TCP_PROXY_DROP_PORTS" "$UDP_PROXY_DROP_PORTS" "$TCP_REDIR_PORTS" "$UDP_REDIR_PORTS"
	[ "$CLIENT_PROXY" = "1" ] && {
		nft "add rule $NFTABLE_NAME PSW_MANGLE counter goto PSW_DEFAULT_PORTS"
		nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 counter goto PSW_DEFAULT_PORTS"
	}
	nft "add rule $NFTABLE_NAME PSW_MANGLE counter return"
	nft "add rule $NFTABLE_NAME PSW_MANGLE_V6 counter return"

	nft "add rule $NFTABLE_NAME mangle_prerouting meta l4proto tcp counter jump PSW_DIVERT"
	nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv4 meta l4proto { tcp, udp } counter jump PSW_MANGLE"
	[ "$PROXY_IPV6" = "1" ] && nft "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv6 meta l4proto { tcp, udp } counter jump PSW_MANGLE_V6"
}

setup_localhost() {
	create_chain PSW_OUTPUT_MANGLE

	nft "add rule $NFTABLE_NAME mangle_output oif lo counter return"
	nft "add rule $NFTABLE_NAME mangle_output meta mark $PROXY_MARK counter return"
	nft "add rule $NFTABLE_NAME mangle_output meta mark $BYPASS_MARK counter return"

	[ "$LOCALHOST_PROXY" = "1" ] || return 0
	add_port_policy PSW_OUTPUT_MANGLE "$TCP_NO_REDIR_PORTS" "$UDP_NO_REDIR_PORTS" \
		"$TCP_PROXY_DROP_PORTS" "$UDP_PROXY_DROP_PORTS" "$TCP_REDIR_PORTS" "$UDP_REDIR_PORTS" 1

	local local_dns dns_address dns_port
	for local_dns in $(echo "$IPT_APPEND_DNS" | tr ',' ' '); do
		dns_address=$(echo "$local_dns" | sed -E 's/(@|\[)?([0-9a-fA-F:.]+)(@|#|$).*/\2/')
		dns_port=$(echo "$local_dns" | sed -nE 's/.*#([0-9]+)$/\1/p')
		if echo "$dns_address" | grep -q ':'; then
			nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto { tcp, udp } ip6 daddr $dns_address th dport ${dns_port:-53} counter return"
		else
			nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto { tcp, udp } ip daddr $dns_address th dport ${dns_port:-53} counter return"
		fi
	done

	nft "add rule $NFTABLE_NAME mangle_output meta nfproto ipv4 meta l4proto { tcp, udp } counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
	[ "$PROXY_IPV6" = "1" ] && nft "add rule $NFTABLE_NAME mangle_output meta nfproto ipv6 meta l4proto { tcp, udp } counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
}

setup_dns() {
	[ "$(config_t_get global dns_redirect 0)" = "1" ] || return 0
	create_chain PSW_DNS_REDIRECT
	nft "add rule $NFTABLE_NAME PSW_DNS_REDIRECT meta l4proto udp udp dport 53 counter redirect to :53 comment \"PSW_DNS_Redirect\""
	nft "add rule $NFTABLE_NAME PSW_DNS_REDIRECT meta l4proto tcp tcp dport 53 counter redirect to :53 comment \"PSW_DNS_Redirect\""
	nft "add rule $NFTABLE_NAME dstnat counter jump PSW_DNS_REDIRECT"
}

setup_ping() {
	[ "$accept_icmp" = "1" ] || [ "$accept_icmpv6" = "1" ] || return 0
	create_chain PSW_PING

	if [ "$accept_icmp" = "1" ] && protocol_available tcp; then
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 jump PSW_POLICY_V4"
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 meta mark $PROXY_MARK counter redirect"
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 meta mark $BYPASS_MARK counter return"
		[ "$TCP_PROXY_MODE" = "proxy" ] && nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 counter redirect"
	fi
	if [ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" = "1" ] && protocol_available tcp; then
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 jump PSW_POLICY_V6"
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 meta mark $PROXY_MARK counter redirect"
		nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 meta mark $BYPASS_MARK counter return"
		[ "$TCP_PROXY_MODE" = "proxy" ] && nft "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 counter redirect"
	fi
	nft "add rule $NFTABLE_NAME PSW_PING return"

	[ "$accept_icmp" = "1" ] && {
		nft "add rule $NFTABLE_NAME dstnat ip protocol icmp icmp type echo-request counter jump PSW_PING"
		nft "add rule $NFTABLE_NAME nat_output ip protocol icmp icmp type echo-request counter jump PSW_PING"
	}
	[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" = "1" ] && {
		nft "add rule $NFTABLE_NAME dstnat meta l4proto icmpv6 icmpv6 type echo-request counter jump PSW_PING"
		nft "add rule $NFTABLE_NAME nat_output meta l4proto icmpv6 icmpv6 type echo-request counter jump PSW_PING"
	}
}

filter_node() {
	local proxy_node="$1" stream proxy_port
	stream=$(echo "$2" | tr 'A-Z' 'a-z')
	proxy_port="${3:-}"

	filter_rules() {
		local node="$1" rule_stream="$2" nested="${3:-0}"
		local type address port ip_type resolved dst_rule
		[ -n "$node" ] && [ "$node" != "nil" ] || return 0
		type=$(echo "$(config_n_get "$node" type)" | tr 'A-Z' 'a-z')
		address=$(config_n_get "$node" address)
		port=$(config_n_get "$node" port)
		for ip_type in ip ip6; do
			[ "$ip_type" = "ip" ] && resolved=$(get_host_ip ipv4 "$address") || resolved=$(get_host_ip ipv6 "$address")
			[ -n "$resolved" ] || continue
			if ! nft "list chain $NFTABLE_NAME PSW_OUTPUT_MANGLE" 2>/dev/null | grep -q "$resolved:$port"; then
				dst_rule="return"
				[ "$nested" = "1" ] && [ -n "$proxy_port" ] && dst_rule="goto PSW_ROUTE_PROXY"
				nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto $rule_stream $ip_type daddr $resolved $rule_stream dport $port $dst_rule comment \"$resolved:$port\"" 2>/dev/null
			fi
		done
	}

	local protocol proxy_type default_node main_node node
	protocol=$(config_n_get "$proxy_node" protocol)
	proxy_type=$(echo "$(config_n_get "$proxy_node" type nil)" | tr 'A-Z' 'a-z')
	[ "$proxy_type" = "nil" ] && return 0
	case "$protocol" in
		_balancing)
			for node in $(config_n_get "$proxy_node" balancing_node); do
				filter_rules "$node" "$stream"
			done
		;;
		_shunt)
			default_node=$(config_n_get "$proxy_node" default_node _direct)
			main_node=$(config_n_get "$proxy_node" main_node nil)
			if [ "$main_node" != "nil" ]; then
				filter_rules "$main_node" "$stream"
			elif [ "$default_node" != "_direct" ] && [ "$default_node" != "_blackhole" ]; then
				filter_rules "$default_node" "$stream"
			fi
		;;
		*) filter_rules "$proxy_node" "$stream" ;;
	esac
}

setup_node_bypass() {
	filter_vpsip
	filter_haproxy
	filter_vps_addr "$(config_n_get "$TCP_NODE" address)" "$(config_n_get "$UDP_NODE" address)"

	# sing-box/Xray may bind an outbound to a dedicated interface. Preserve the
	# interface bypass in addition to address-based VPS sets to prevent loops.
	local iface
	for iface in $(ls "$TMP_IFACE_PATH" 2>/dev/null); do
		nft "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE oifname \"$iface\" counter return comment \"node interface bypass\""
	done

	local id enabled node port stream
	if [ "$SOCKS_ENABLED" = "1" ]; then
		for id in $(uci show "$CONFIG" | grep '=socks' | cut -d. -f2 | cut -d= -f1); do
			enabled=$(config_n_get "$id" enabled 0)
			node=$(config_n_get "$id" node nil)
			[ "$enabled" = "1" ] && [ "$node" != "nil" ] || continue
			filter_node "$node" TCP
			filter_node "$node" UDP
		done
	fi
	if [ "$ENABLED_DEFAULT_ACL" = "1" ]; then
		for stream in TCP UDP; do
			[ "$stream" = "TCP" ] && node="$TCP_NODE" && port="$TCP_REDIR_PORT"
			[ "$stream" = "UDP" ] && node="$UDP_NODE" && port="$UDP_REDIR_PORT"
			[ "$node" != "nil" ] && filter_node "$node" "$stream" "$port"
		done
	fi
}

setup_routes() {
	while ip rule del fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
	ip route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null
	ip rule add fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE"
	if [ "$iproute_shunt" = "1" ]; then
		ip route replace default via "$iproute_shunt_gw_v4" dev "$iproute_shunt_interface" table "$PROXY_ROUTE_TABLE"
	else
		ip route replace local 0.0.0.0/0 dev lo table "$PROXY_ROUTE_TABLE"
	fi

	while ip -6 rule del fwmark "$PROXY_MARK" table "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
	ip -6 route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null
	[ "$PROXY_IPV6" = "1" ] || return 0
	ip -6 rule add fwmark "$PROXY_MARK" table "$PROXY_ROUTE_TABLE"
	if [ "$iproute_shunt" = "1" ]; then
		ip -6 route replace default via "$iproute_shunt_gw_v6" dev "$iproute_shunt_interface" table "$PROXY_ROUTE_TABLE"
	else
		ip -6 route replace local ::/0 dev lo table "$PROXY_ROUTE_TABLE"
	fi
}

setup_flow_offload() {
	create_chain PSW_HWNAT_PASS
	nft delete flowtable $NFTABLE_NAME ft 2>/dev/null
	[ "$iproute_shunt" = "1" ] || return 0
	nft "add flowtable $NFTABLE_NAME ft { hook ingress priority filter - 1; devices = { $iproute_shunt_offloading_interface }; flags offload; counter; }"
	nft "add rule $NFTABLE_NAME hwnat_pass meta l4proto { tcp, udp } counter jump PSW_HWNAT_PASS"
	nft "add rule $NFTABLE_NAME PSW_HWNAT_PASS meta l4proto { tcp, udp } meta mark != $PROXY_MARK ct mark != $PROXY_MARK flow add @ft comment \"直连流量硬件加速\""
}

add_firewall_rule() {
	iproute_shunt=$(config_t_get global_forwarding iproute_shunt 0)
	iproute_shunt_gw_v4=$(config_t_get global_forwarding iproute_shunt_gw_v4 192.168.1.1)
	iproute_shunt_gw_v6=$(config_t_get global_forwarding iproute_shunt_gw_v6 fd00::114:514)
	iproute_shunt_interface=$(config_t_get global_forwarding iproute_shunt_interface br-lan)
	iproute_shunt_offloading_interface=$(config_t_get global_forwarding iproute_shunt_offloading_interface lan1,lan2,lan3,wan)
	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	echolog "开始加载 nftables 规则（TCP/UDP TPROXY-first）..."
	gen_nft_tables
	setup_sets
	setup_proxy_actions
	setup_global_policy
	setup_client_chains
	setup_localhost

	# Direct MACs return before every dstnat consumer, so DNS and ping cannot
	# become a hidden partial-proxy path for Direct ACL devices.
	nft "add rule $NFTABLE_NAME dstnat ether saddr @$NFTSET_DIRECT_MACS counter return"
	setup_ping
	setup_dns
	setup_node_bypass
	setup_routes
	setup_flow_offload

	bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
	echo -n "$bridge_nf_ipt" > "$TMP_PATH/bridge_nf_ipt"
	sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
	if [ "$PROXY_IPV6" = "1" ]; then
		bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
		echo -n "$bridge_nf_ip6t" > "$TMP_PATH/bridge_nf_ip6t"
		sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
	fi
	echolog "nftables 规则加载完成。"
}

del_firewall_rule() {
	nft flush table $NFTABLE_NAME 2>/dev/null
	nft delete table $NFTABLE_NAME 2>/dev/null
	while ip rule del fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
	ip route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null
	while ip -6 rule del fwmark "$PROXY_MARK" table "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
	ip -6 route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null
	$DIR/app.sh echolog "删除 nftables、flowtable 和策略路由规则完成。"
}

flush_nftset() {
	$DIR/app.sh echolog "清空 Passwall NFTSET。"
	local name
	for name in $(nft -a list sets 2>/dev/null | awk '/set passwall_/{print $2}'); do
		nft flush set $NFTABLE_NAME "$name" 2>/dev/null
	done
}

flush_nftset_reload() {
	del_firewall_rule
	rm -rf /tmp/singbox_passwall* /tmp/etc/passwall_tmp/dnsmasq*
	/etc/init.d/passwall reload
}

flush_include() {
	[ -n "$FWI" ] && echo '#!/bin/sh' > "$FWI"
}

gen_include() {
	[ -n "$FWI" ] || return 0
	flush_include
	local nft_file="$TMP_PATH/passwall.nft"
	echo '#!/usr/sbin/nft -f' > "$nft_file"
	nft list table $NFTABLE_NAME >> "$nft_file"
	cat <<-EOF >> "$FWI"
	[ -z "\$(nft list chain $NFTABLE_NAME mangle_prerouting 2>/dev/null | grep PSW_MANGLE)" ] && nft -f "$nft_file"
	EOF
}

start() {
	[ "$ENABLED_DEFAULT_ACL" = "0" ] && [ "$ENABLED_ACLS" = "0" ] && return 0
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	flush_include
}

arg1=$1
shift
case "$arg1" in
	flush_nftset) flush_nftset ;;
	flush_nftset_reload) flush_nftset_reload ;;
	get_wan_ip) get_wan_ip ;;
	get_wan6_ip) get_wan6_ip ;;
	stop) stop ;;
	start) start ;;
	*) ;;
esac
