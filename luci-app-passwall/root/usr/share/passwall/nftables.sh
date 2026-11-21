#!/bin/sh

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

. /usr/share/passwall/network.sh

FWI=$(uci -q get firewall.passwall.path 2>/dev/null)

factor() {
	if [ -z "$1" ] || [ -z "$2" ] || [ "$1" = "1:65535" ]; then
		echo ""
	else
		echo "$2 {$(echo "$1" | sed 's/:/-/g; s/,/, /g')}"
	fi
}

# Rule builders only print commands. The caller owns the service lock.
nft_emit() {
	printf '%s\n' "$*"
}

create_chain() {
	nft_emit "add chain $NFTABLE_NAME $1"
}

gen_nft_tables() {
	cat <<-EOF
	table $NFTABLE_NAME {
		chain dstnat { type nat hook prerouting priority dstnat - 1; policy accept; }
		chain mangle_prerouting { type filter hook prerouting priority mangle - 1; policy accept; }
		chain mangle_output { type route hook output priority mangle - 1; policy accept; }
		chain nat_output { type nat hook output priority -1; policy accept; }
		chain hwnat_pass { type filter hook forward priority filter - 1; policy accept; }
	}
	EOF
}

insert_nftset() {
	local name="$1" timeout="$2" elements
	shift 2
	[ -n "$*" ] || return 0
	case "$timeout" in
		-1) elements=$(printf '%s' "$*" | sed 's/[[:space:]]\+/, /g') ;;
		0) elements=$(printf '%s' "$*" | sed 's/[[:space:]]\+/ timeout 3650d, /g; s/$/ timeout 3650d/') ;;
		*) elements=$(printf '%s' "$*" | sed "s/[[:space:]]\+/ timeout $timeout, /g; s/$/ timeout $timeout/") ;;
	esac
	nft_emit "add element $NFTABLE_NAME $name { $elements }"
}

gen_nftset() {
	local name="$1" type="$2" timeout="$3" element_timeout="$4"
	shift 4
	if [ "$timeout" = 0 ]; then
		nft_emit "add set $NFTABLE_NAME $name { type $type; flags interval, timeout; auto-merge; }"
	else
		nft_emit "add set $NFTABLE_NAME $name { type $type; flags interval, timeout; timeout $timeout; gc-interval $timeout; auto-merge; }"
	fi
	insert_nftset "$name" "$element_timeout" "$@"
}

gen_lanlist() {
	grep -v '^#' "$RULES_PATH/lanlist_ipv4" | sed '/^$/d'
}

gen_lanlist_6() {
	grep -v '^#' "$RULES_PATH/lanlist_ipv6" | sed '/^$/d'
}

load_rule_set() {
	gen_nftset "$1" "$2" 2d 0 $(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$RULES_PATH/$3")
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

lan_networks() {
	local logical_if="$1" subnets4 subnets6 device
	[ -n "$logical_if" ] || return 0
	network_get_subnets subnets4 "$logical_if"
	network_get_subnets6 subnets6 "$logical_if"
	# network_get_subnets* is preferred; the device fallback covers unusual
	# netifd state while retaining all bridge/VLAN addresses.
	if [ -z "$subnets4$subnets6" ]; then
		network_get_device device "$logical_if"
		[ -n "$device" ] || return 0
		subnets4=$(ip -o -4 address show dev "$device" 2>/dev/null | awk '{print $4}')
		subnets6=$(ip -o -6 address show dev "$device" scope global 2>/dev/null | awk '{print $4}')
	fi
	printf '%s\n' $subnets4 $subnets6
}

setup_lan_sets() {
	local logical_if subnets
	network_flush_cache
	subnets=$(
		lan_networks lan
		for logical_if in $iproute_shunt_logical_interfaces; do
			[ "$logical_if" = lan ] || lan_networks "$logical_if"
		done
	)
	# Auto-merge sees overlaps between interface prefixes and reserved ranges
	# together when each set is populated by a single element command.
	gen_nftset "$NFTSET_LANLIST" ipv4_addr 0 -1 $(gen_lanlist) \
		$(printf '%s\n' "$subnets" | grep -vF :) $(get_wan_ip)
	gen_nftset "$NFTSET_LANLIST6" ipv6_addr 0 -1 $(gen_lanlist_6) \
		$(printf '%s\n' "$subnets" | grep -F :) $(get_wan6_ip)
}

setup_sets() {
	setup_lan_sets
	gen_nftset "$NFTSET_VPSLIST" ipv4_addr 0 0
	gen_nftset "$NFTSET_GFW" ipv4_addr 2d 0
	load_rule_set "$NFTSET_CHN" ipv4_addr chnroute
	gen_nftset "$NFTSET_BLACKLIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/proxy_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_WHITELIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/direct_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_BLOCKLIST" ipv4_addr 2d 0 $(grep -v '^#' "$RULES_PATH/block_ip" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
	gen_nftset "$NFTSET_SHUNTLIST" ipv4_addr 0 0

	gen_nftset "$NFTSET_VPSLIST6" ipv6_addr 0 0
	gen_nftset "$NFTSET_GFW6" ipv6_addr 2d 0
	load_rule_set "$NFTSET_CHN6" ipv6_addr chnroute6
	gen_nftset "$NFTSET_BLACKLIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/proxy_ip" | grep -E ':')
	gen_nftset "$NFTSET_WHITELIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/direct_ip" | grep -E ':')
	gen_nftset "$NFTSET_BLOCKLIST6" ipv6_addr 2d 0 $(grep -v '^#' "$RULES_PATH/block_ip" | grep -E ':')
	gen_nftset "$NFTSET_SHUNTLIST6" ipv6_addr 0 0

	nft_emit "add set $NFTABLE_NAME $NFTSET_DIRECT_MACS { type ether_addr; }"

	local shunt_id shunt_ids
	shunt_ids=$(config_ids shunt_rules)
	for shunt_id in $shunt_ids; do
		# Old Geo rules must be skipped as a whole, matching the core and DNS generators.
		if { config_n_get "$shunt_id" source | tr " " "\n"; config_n_get "$shunt_id" domain_list; config_n_get "$shunt_id" ip_list; } |
			grep -Eq '^[[:space:]]*(geoip|geosite|ext):'; then
			continue
		fi
		insert_nftset "$NFTSET_SHUNTLIST" -1 $(config_n_get "$shunt_id" ip_list | tr -s '\r\n' '\n' | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
		insert_nftset "$NFTSET_SHUNTLIST6" -1 $(config_n_get "$shunt_id" ip_list | tr -s '\r\n' '\n' | grep -E ':')
	done

	local isp
	for isp in $ISP_DNS; do
		insert_nftset "$NFTSET_WHITELIST" 0 "$isp"
	done
	for isp in $ISP_DNS6; do
		insert_nftset "$NFTSET_WHITELIST6" 0 "$isp"
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

node_addresses() {
	local node
	for node in $(config_ids nodes); do config_n_get "$node" address; done
}

filter_vpsip() {
	insert_nftset "$NFTSET_VPSLIST" -1 $(node_addresses | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$')
	insert_nftset "$NFTSET_VPSLIST6" -1 $(node_addresses | grep -E ':')
}

setup_proxy_actions() {
	create_chain PSW_MARK
	nft_emit "add rule $NFTABLE_NAME PSW_MARK counter meta mark set $PROXY_MARK ct mark set mark return"

	local chain family port
	for chain in PSW_PROXY_TCP4 PSW_PROXY_UDP4 PSW_PROXY_TCP6 PSW_PROXY_UDP6; do
		create_chain "$chain"
	done

	if [ "$iproute_shunt" = "1" ]; then
		for chain in PSW_PROXY_TCP4 PSW_PROXY_UDP4 PSW_PROXY_TCP6 PSW_PROXY_UDP6; do
			nft_emit "add rule $NFTABLE_NAME $chain goto PSW_MARK"
		done
	else
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_TCP4 jump PSW_MARK"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_TCP4 meta l4proto tcp counter tproxy ip to :$TCP_REDIR_PORT return"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_UDP4 jump PSW_MARK"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_UDP4 meta l4proto udp counter tproxy ip to :$UDP_REDIR_PORT return"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_TCP6 jump PSW_MARK"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_TCP6 meta l4proto tcp counter tproxy ip6 to :$TCP_REDIR_PORT return"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_UDP6 jump PSW_MARK"
		nft_emit "add rule $NFTABLE_NAME PSW_PROXY_UDP6 meta l4proto udp counter tproxy ip6 to :$UDP_REDIR_PORT return"
	fi

	create_chain PSW_ROUTE_PROXY
	nft_emit "add rule $NFTABLE_NAME PSW_ROUTE_PROXY goto PSW_MARK"
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

	nft_emit "add rule $NFTABLE_NAME $chain $daddr @$lan_set counter meta mark set $BYPASS_MARK return"
	nft_emit "add rule $NFTABLE_NAME $chain $daddr @$vps_set counter meta mark set $BYPASS_MARK return"
	[ "$USE_DIRECT_LIST" = "1" ] && nft_emit "add rule $NFTABLE_NAME $chain $daddr @$direct_set counter meta mark set $BYPASS_MARK return"
	[ "$USE_BLOCK_LIST" = "1" ] && nft_emit "add rule $NFTABLE_NAME $chain $daddr @$block_set counter drop"
	nft_emit "add rule $NFTABLE_NAME $chain $daddr @$shunt_set counter goto PSW_MARK"
	[ "$USE_PROXY_LIST" = "1" ] && nft_emit "add rule $NFTABLE_NAME $chain $daddr @$proxy_set counter goto PSW_MARK"
	[ "$USE_GFW_LIST" = "1" ] && nft_emit "add rule $NFTABLE_NAME $chain $daddr @$gfw_set counter goto PSW_MARK"
	case "$CHN_LIST" in
		direct) nft_emit "add rule $NFTABLE_NAME $chain $daddr @$chn_set counter meta mark set $BYPASS_MARK return" ;;
		proxy) nft_emit "add rule $NFTABLE_NAME $chain $daddr @$chn_set counter goto PSW_MARK" ;;
	esac
	nft_emit "add rule $NFTABLE_NAME $chain return"
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

	nft_emit "add rule $NFTABLE_NAME $chain $match jump $policy_chain"
	if [ "$result" = "drop" ]; then
		nft_emit "add rule $NFTABLE_NAME $chain $match meta mark $PROXY_MARK counter drop"
		nft_emit "add rule $NFTABLE_NAME $chain $match meta mark $BYPASS_MARK counter return"
		[ "$default_mode" = "proxy" ] && nft_emit "add rule $NFTABLE_NAME $chain $match counter drop"
	else
		nft_emit "add rule $NFTABLE_NAME $chain $match meta mark $PROXY_MARK counter goto $action_chain"
		nft_emit "add rule $NFTABLE_NAME $chain $match meta mark $BYPASS_MARK counter return"
		[ "$default_mode" = "proxy" ] && nft_emit "add rule $NFTABLE_NAME $chain $match counter goto $action_chain"
	fi
	nft_emit "add rule $NFTABLE_NAME $chain $match counter return"
}

add_port_policy() {
	local chain="$1" tcp_bypass="$2" udp_bypass="$3" tcp_drop="$4" udp_drop="$5" tcp_proxy="$6" udp_proxy="$7" output_path="${8:-0}"
	local family family_match
	for family in 4 6; do
		[ "$family" = "4" ] && family_match="meta nfproto ipv4" || family_match="meta nfproto ipv6"
		[ "$tcp_bypass" != "disable" ] && nft_emit "add rule $NFTABLE_NAME $chain $family_match meta l4proto tcp $(factor "$tcp_bypass" 'tcp dport') counter return"
		[ "$udp_bypass" != "disable" ] && nft_emit "add rule $NFTABLE_NAME $chain $family_match meta l4proto udp $(factor "$udp_bypass" 'udp dport') counter return"
		add_policy_port_result "$chain" "$family" tcp "$tcp_drop" drop "$(protocol_default_mode tcp)" "$output_path"
		add_policy_port_result "$chain" "$family" udp "$udp_drop" drop "$(protocol_default_mode udp)" "$output_path"
		add_policy_port_result "$chain" "$family" tcp "$tcp_proxy" proxy "$(protocol_default_mode tcp)" "$output_path"
		add_policy_port_result "$chain" "$family" udp "$udp_proxy" proxy "$(protocol_default_mode udp)" "$output_path"
	done
	nft_emit "add rule $NFTABLE_NAME $chain counter return"
}

valid_macs_csv() {
	local item mac separator=""
	for item in $1; do
		if echo "$item" | grep -Eiq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
			mac=$(echo "$item" | tr 'a-f' 'A-F')
			printf '%s%s' "$separator" "$mac"
			separator=", "
		fi
	done
}

mac_match() {
	local macs
	macs=$(valid_macs_csv "$1")
	[ -n "$macs" ] && echo "ether saddr { $macs }"
}

acl_ids() {
	config_ids acl_rule
}

acl_value() {
	local sid="$1" key="$2" fallback="$3" value
	value=$(config_n_get "$sid" "$key" "$fallback")
	[ "$value" = "default" ] && value=$(config_t_get global_forwarding "$key" "$fallback")
	echo "$value"
}

setup_acl() {
	[ "${ENABLED:-0}" = "1" ] || return 0
	local sid sources direct remarks macs mac_csv chain

	# Aggregate every Direct ACL first. This gives Direct priority even if the
	# same MAC also appears in an earlier normal ACL.
	for sid in $(acl_ids); do
		[ "$(config_n_get "$sid" enabled 0)" = "1" ] || continue
		direct=$(config_n_get "$sid" direct 0)
		[ "$direct" = "1" ] || continue
		sources=$(config_n_get "$sid" sources)
		mac_csv=$(valid_macs_csv "$sources")
		[ -n "$mac_csv" ] && nft_emit "add element $NFTABLE_NAME $NFTSET_DIRECT_MACS { $mac_csv }" 2>/dev/null
	done

	for sid in $(acl_ids); do
		[ "$(config_n_get "$sid" enabled 0)" = "1" ] || continue
		[ "$(config_n_get "$sid" direct 0)" = "1" ] && continue
		sources=$(config_n_get "$sid" sources)
		macs=$(mac_match "$sources")
		[ -n "$macs" ] || {
			echolog 转发 "设备策略[$sid] 没有有效 MAC 地址，已跳过"
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
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE $macs counter goto $chain"
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 $macs counter goto $chain"
		remarks=$(config_n_get "$sid" remarks "$sid")
		debuglog 转发 "设备策略：$remarks"
	done
}

setup_client_chains() {
	create_chain PSW_DIVERT
	nft_emit "add rule $NFTABLE_NAME PSW_DIVERT meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK ct mark set mark counter accept"

	create_chain PSW_MANGLE
	create_chain PSW_MANGLE_V6
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE ether saddr @$NFTSET_DIRECT_MACS counter return"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 ether saddr @$NFTSET_DIRECT_MACS counter return"

	# DNS hijack is a global NAT decision. Let client DNS leave mangle before
	# any ACL/default TPROXY rule so dstnat can redirect it to the router's DNS.
	# Marked localhost DNS must still reach TPROXY after routing back through lo.
	if [ "$(config_t_get global dns_redirect 1)" = "1" ]; then
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE iifname != \"lo\" meta l4proto { tcp, udp } th dport 53 counter return"
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 iifname != \"lo\" meta l4proto { tcp, udp } th dport 53 counter return"
	fi

	# Locally generated marked packets return through lo only with local TPROXY.
	# PBR mode routes them directly to the configured external gateway instead.
	if [ "$iproute_shunt" != "1" ]; then
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE iif lo meta mark $PROXY_MARK meta l4proto tcp counter goto PSW_PROXY_TCP4"
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE iif lo meta mark $PROXY_MARK meta l4proto udp counter goto PSW_PROXY_UDP4"
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo meta mark $PROXY_MARK meta l4proto tcp counter goto PSW_PROXY_TCP6"
		nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo meta mark $PROXY_MARK meta l4proto udp counter goto PSW_PROXY_UDP6"
	fi
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE iif lo counter return"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 iif lo counter return"

	setup_acl

	create_chain PSW_DEFAULT_PORTS
	add_port_policy PSW_DEFAULT_PORTS "$TCP_NO_REDIR_PORTS" "$UDP_NO_REDIR_PORTS" \
		"$TCP_PROXY_DROP_PORTS" "$UDP_PROXY_DROP_PORTS" "$TCP_REDIR_PORTS" "$UDP_REDIR_PORTS"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE counter goto PSW_DEFAULT_PORTS"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 counter goto PSW_DEFAULT_PORTS"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE counter return"
	nft_emit "add rule $NFTABLE_NAME PSW_MANGLE_V6 counter return"

	nft_emit "add rule $NFTABLE_NAME mangle_prerouting meta l4proto tcp counter jump PSW_DIVERT"
	nft_emit "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv4 meta l4proto { tcp, udp } counter jump PSW_MANGLE"
	[ "$PROXY_IPV6" = "1" ] && nft_emit "add rule $NFTABLE_NAME mangle_prerouting meta nfproto ipv6 meta l4proto { tcp, udp } counter jump PSW_MANGLE_V6"
}

setup_localhost() {
	create_chain PSW_OUTPUT_MANGLE

	nft_emit "add rule $NFTABLE_NAME mangle_output oif lo counter return"
	nft_emit "add rule $NFTABLE_NAME mangle_output meta mark $PROXY_MARK counter return"
	nft_emit "add rule $NFTABLE_NAME mangle_output meta mark $BYPASS_MARK counter return"

	[ "$LOCALHOST_PROXY" = "1" ] || return 0
	add_port_policy PSW_OUTPUT_MANGLE "$TCP_NO_REDIR_PORTS" "$UDP_NO_REDIR_PORTS" \
		"$TCP_PROXY_DROP_PORTS" "$UDP_PROXY_DROP_PORTS" "$TCP_REDIR_PORTS" "$UDP_REDIR_PORTS" 1

	local local_dns dns_address dns_port
	for local_dns in $(echo "$IPT_APPEND_DNS" | tr ',' ' '); do
		dns_address=${local_dns%#*}
		dns_port=${local_dns##*#}
		[ "$dns_address" != "$local_dns" ] || dns_port=53
		if echo "$dns_address" | grep -q ':'; then
			nft_emit "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto { tcp, udp } ip6 daddr $dns_address th dport ${dns_port:-53} counter return"
		else
			nft_emit "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto { tcp, udp } ip daddr $dns_address th dport ${dns_port:-53} counter return"
		fi
	done

	nft_emit "add rule $NFTABLE_NAME mangle_output meta nfproto ipv4 meta l4proto { tcp, udp } counter jump PSW_OUTPUT_MANGLE"
	[ "$PROXY_IPV6" = "1" ] && nft_emit "add rule $NFTABLE_NAME mangle_output meta nfproto ipv6 meta l4proto { tcp, udp } counter jump PSW_OUTPUT_MANGLE"
}

setup_dns() {
	[ "$(config_t_get global dns_redirect 1)" = "1" ] || return 0
	create_chain PSW_DNS_REDIRECT
	nft_emit "add rule $NFTABLE_NAME PSW_DNS_REDIRECT meta l4proto udp udp dport 53 counter redirect to :53"
	nft_emit "add rule $NFTABLE_NAME PSW_DNS_REDIRECT meta l4proto tcp tcp dport 53 counter redirect to :53"
	nft_emit "add rule $NFTABLE_NAME dstnat iifname != \"lo\" counter jump PSW_DNS_REDIRECT"
}

setup_ping() {
	[ "$accept_icmp" = "1" ] || [ "$accept_icmpv6" = "1" ] || return 0
	create_chain PSW_PING

	if [ "$accept_icmp" = "1" ] && protocol_available tcp; then
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 jump PSW_POLICY_V4"
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 meta mark $PROXY_MARK counter redirect"
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 meta mark $BYPASS_MARK counter return"
		[ "$TCP_PROXY_MODE" = "proxy" ] && nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv4 counter redirect"
	fi
	if [ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" = "1" ] && protocol_available tcp; then
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 jump PSW_POLICY_V6"
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 meta mark $PROXY_MARK counter redirect"
		nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 meta mark $BYPASS_MARK counter return"
		[ "$TCP_PROXY_MODE" = "proxy" ] && nft_emit "add rule $NFTABLE_NAME PSW_PING meta nfproto ipv6 counter redirect"
	fi
	nft_emit "add rule $NFTABLE_NAME PSW_PING return"

	[ "$accept_icmp" = "1" ] && {
		nft_emit "add rule $NFTABLE_NAME dstnat ip protocol icmp icmp type echo-request counter jump PSW_PING"
		nft_emit "add rule $NFTABLE_NAME nat_output ip protocol icmp icmp type echo-request counter jump PSW_PING"
	}
	[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" = "1" ] && {
		nft_emit "add rule $NFTABLE_NAME dstnat meta l4proto icmpv6 icmpv6 type echo-request counter jump PSW_PING"
		nft_emit "add rule $NFTABLE_NAME nat_output meta l4proto icmpv6 icmpv6 type echo-request counter jump PSW_PING"
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
			dst_rule="return"
			[ "$nested" = "1" ] && [ -n "$proxy_port" ] && dst_rule="goto PSW_ROUTE_PROXY"
			nft_emit "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE meta l4proto $rule_stream $ip_type daddr $resolved $rule_stream dport $port $dst_rule"
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
	filter_vps_addr "$(config_n_get "$TCP_NODE" address)" "$(config_n_get "$UDP_NODE" address)"

	# Xray may bind an outbound to a dedicated interface. Preserve the
	# interface bypass in addition to address-based VPS sets to prevent loops.
	local iface
	for iface in $(ls "$TMP_IFACE_PATH" 2>/dev/null); do
		nft_emit "insert rule $NFTABLE_NAME PSW_OUTPUT_MANGLE oifname \"$iface\" counter return"
	done

	local node port stream
	if [ "$ENABLED_DEFAULT_ACL" = "1" ]; then
		for stream in TCP UDP; do
			[ "$stream" = "TCP" ] && node="$TCP_NODE" && port="$TCP_REDIR_PORT"
			[ "$stream" = "UDP" ] && node="$UDP_NODE" && port="$UDP_REDIR_PORT"
			[ "$node" != "nil" ] && filter_node "$node" "$stream" "$port"
		done
	fi
}

nft_offload_devices() {
	QUIET=1 ucode "$APP_PATH/offload.uc"
}

nft_read_config() {
	iproute_shunt=$(config_t_get global_forwarding iproute_shunt 0)
	iproute_shunt_gw_v4=$(config_t_get global_forwarding iproute_shunt_gw_v4)
	iproute_shunt_gw_v6=$(config_t_get global_forwarding iproute_shunt_gw_v6)
	iproute_shunt_interface=$(config_t_get global_forwarding iproute_shunt_interface)
	iproute_shunt_offloading_interface=""
	iproute_shunt_logical_interfaces=""
	if [ "$iproute_shunt" = 1 ]; then
		if ! iproute_shunt_offloading_interface=$(nft_offload_devices 2>/dev/null); then
			iproute_shunt_offloading_interface=""
			debuglog 转发 "无法获取硬件加速接口，PBR 继续使用普通转发"
		fi
		iproute_shunt_logical_interfaces=$(passwall_proxy_interfaces "$iproute_shunt_interface")
	fi
	accept_icmp=$(config_t_get global_forwarding accept_icmp 1)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 1)
}

setup_flow_offload() {
	[ "$iproute_shunt" = 1 ] || return 0
	[ -n "$iproute_shunt_offloading_interface" ] || return 0
	create_chain PSW_HWNAT_PASS
	nft_emit "add flowtable $NFTABLE_NAME ft { hook ingress priority filter - 1; devices = { $iproute_shunt_offloading_interface }; flags offload; counter; }"
	nft_emit "add rule $NFTABLE_NAME hwnat_pass meta l4proto { tcp, udp } counter jump PSW_HWNAT_PASS"
	nft_emit "add rule $NFTABLE_NAME PSW_HWNAT_PASS meta l4proto { tcp, udp } meta mark != $PROXY_MARK ct mark != $PROXY_MARK flow add @ft"
	nft_emit "add rule $NFTABLE_NAME PSW_HWNAT_PASS meta l4proto { tcp, udp } ct direction original meta mark $PROXY_MARK counter flow add @ft"
}

nft_generate() {
	gen_nft_tables
	setup_sets
	setup_proxy_actions
	setup_global_policy
	setup_client_chains
	setup_localhost
	nft_emit "add rule $NFTABLE_NAME dstnat ether saddr @$NFTSET_DIRECT_MACS counter return"
	setup_ping
	setup_dns
	setup_node_bypass
	setup_flow_offload
}

nft_present() {
	nft list tables | grep -Fxq "table $NFTABLE_NAME"
}

nft_batch() {
	# Keep delete and recreate in one transaction; never flush the live table first.
	if nft_present; then
		printf 'delete table %s\n' "$NFTABLE_NAME"
	fi
	cat "$1"
}

nft_prepare() {
	nft_generate > "$1/rules.nft"
}

nft_check() {
	nft_batch "$1/rules.nft" > "$1/batch.nft" || return 1
	if ! nft -c -f "$1/batch.nft" 2> "$1/nft.error"; then
		echolog 转发 "规则校验失败：$(cat "$1/nft.error")"
		return 1
	fi
}

nft_commit() {
	if cmp -s "$1/rules.nft" "$STATE_PATH/rules.nft" && nft_present; then
		return 0
	fi
	# fw4 may have removed the table. Build the atomic replacement from live state.
	nft_batch "$1/rules.nft" > "$1/batch.nft" || return 1
	if ! nft -f "$1/batch.nft" 2> "$1/nft.error"; then
		echolog 转发 "规则提交失败，保留原规则：$(cat "$1/nft.error")"
		return 1
	fi
}

nft_restore() {
	[ -s "$STATE_PATH/rules.nft" ] || return 1
	nft_batch "$STATE_PATH/rules.nft" | nft -f -
}

nft_routes_save() {
	ip -4 route save table "$PROXY_ROUTE_TABLE" > "$1/routes4" 2>/dev/null || :
	ip -6 route save table "$PROXY_ROUTE_TABLE" > "$1/routes6" 2>/dev/null || :
	ip -4 rule show | grep -F "fwmark $PROXY_MARK lookup $PROXY_ROUTE_TABLE" > "$1/rule4" || :
	ip -6 rule show | grep -F "fwmark $PROXY_MARK lookup $PROXY_ROUTE_TABLE" > "$1/rule6" || :
}

nft_routes_restore() {
	local family
	for family in 4 6; do
		ip -$family route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null
		ip -$family route restore < "$1/routes$family"
		if [ ! -s "$1/rule$family" ]; then
			while ip -$family rule del fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
		fi
	done
}

nft_pbr_ready() {
	local family="$1" device="$2"
	[ -e "/sys/class/net/$device" ] &&
		[ "$(cat "/sys/class/net/$device/operstate")" != down ] || return 1
	# Link-up precedes DHCP and IPv6 DAD. Keep the guard until this family
	# has a usable address; a later hotplug event will install its gateway.
	[ -n "$(ip -"$family" -o address show dev "$device" 2>/dev/null | grep -Ev 'tentative|dadfailed')" ]
}

nft_routes() {
	local family gateway
	for family in 4 6; do
		[ "$family" = 4 ] || [ "$PROXY_IPV6" = 1 ] || continue
		# This guard remains when a link disappears, so PROXY cannot fall through to main.
		ip -$family route replace unreachable default metric 32767 table "$PROXY_ROUTE_TABLE" || return 1
		if [ "$iproute_shunt" = 1 ]; then
			[ "$family" = 4 ] && gateway="$iproute_shunt_gw_v4" || gateway="$iproute_shunt_gw_v6"
			if ! nft_pbr_ready "$family" "$iproute_shunt_interface"; then
				ip -$family route del default metric 100 table "$PROXY_ROUTE_TABLE" 2>/dev/null || :
				echolog 转发 "PBR 接口 $iproute_shunt_interface 未就绪，IPv$family 代理暂不可达"
			else
				ip -$family route replace default via "$gateway" dev "$iproute_shunt_interface" metric 100 table "$PROXY_ROUTE_TABLE" || return 1
			fi
		else
			ip -$family route replace local default dev lo metric 100 table "$PROXY_ROUTE_TABLE" || return 1
		fi
		if ! ip -$family rule show | grep -Fq "fwmark $PROXY_MARK lookup $PROXY_ROUTE_TABLE"; then
			ip -$family rule add pref 32765 fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE" || return 1
		fi
	done
}

nft_stop() {
	local failed=0
	if nft_present; then
		nft delete table $NFTABLE_NAME || failed=1
	fi
	local family
	for family in 4 6; do
		while ip -$family rule del fwmark "$PROXY_MARK" lookup "$PROXY_ROUTE_TABLE" 2>/dev/null; do :; done
		ip -$family route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null || :
	done
	return "$failed"
}

nft_network_snapshot() {
	local interface device key family
	printf 'offload_devices=%s\n' "$iproute_shunt_offloading_interface"
	for key in iproute_shunt iproute_shunt_gw_v4 iproute_shunt_gw_v6 iproute_shunt_interface; do
		printf '%s=%s\n' "$key" "$(config_t_get global_forwarding "$key")"
	done
	network_flush_cache
	for interface in $(printf '%s\n' wan wan6 lan $iproute_shunt_logical_interfaces | sort -u); do
		network_get_device device "$interface"
		printf '%s %s\n' "$interface" "$device"
		[ -n "$device" ] || continue
		cat "/sys/class/net/$device/ifindex" "/sys/class/net/$device/operstate" 2>/dev/null
		ip -o address show dev "$device" 2>/dev/null | awk '{print $2, $3, $4}'
	done
	if [ "$iproute_shunt" = 1 ]; then
		printf 'proxy_device=%s\n' "$iproute_shunt_interface"
		cat "/sys/class/net/$iproute_shunt_interface/ifindex" "/sys/class/net/$iproute_shunt_interface/operstate" 2>/dev/null
		ip -o address show dev "$iproute_shunt_interface" 2>/dev/null | awk '{print $2, $3, $4}'
		# DAD can finish without changing an address, route or link state.
		# Include the same readiness decision used when installing PBR routes.
		for family in 4 6; do
			if nft_pbr_ready "$family" "$iproute_shunt_interface"; then
				printf 'proxy_ready%s=1\n' "$family"
			else
				printf 'proxy_ready%s=0\n' "$family"
			fi
		done
	fi
	ip -4 route show default
	ip -6 route show default
	cat "$RESOLVFILE" 2>/dev/null
}

nft_bridge_start() {
	local key value
	for key in ipt ip6t; do
		[ "$key" = ipt ] && value=iptables || value=ip6tables
		if [ ! -e "$STATE_PATH/bridge_nf_$key" ]; then
			sysctl -e -n "net.bridge.bridge-nf-call-$value" > "$STATE_PATH/bridge_nf_$key"
		fi
		sysctl -w "net.bridge.bridge-nf-call-$value=0" >/dev/null 2>&1 || :
	done
}

nft_bridge_stop() {
	local key name value
	for key in ipt ip6t; do
		[ "$key" = ipt ] && name=iptables || name=ip6tables
		[ -s "$STATE_PATH/bridge_nf_$key" ] || continue
		value=$(cat "$STATE_PATH/bridge_nf_$key")
		sysctl -w "net.bridge.bridge-nf-call-$name=$value" >/dev/null 2>&1 || :
	done
}

nft_include() {
	[ -n "$FWI" ] || return 0
	mkdir -p "$(dirname "$FWI")"
	cat > "$FWI" <<-'EOF'
	#!/bin/sh
	[ "${PASSWALL_FW_RELOAD:-0}" != 1 ] || exit 0
	[ -f /var/run/passwall/running ] || exit 0
	/etc/init.d/passwall reload firewall 9>&- 1000>&- >/dev/null 2>&1 &
	EOF
}
